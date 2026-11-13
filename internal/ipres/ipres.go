// Package ipres IP 资源入库：static 源从数据库加载，api 源周期抓取解析。
// 对应 malenia 的 outbound/downloader/IpDownloader + malenia-api 的 GroovyIpResourceHandler
// （Go 版用内置解析器替代 Groovy 脚本：支持 ip:port 与 ip:port,country,city,lng,lat 行格式）
package ipres

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"malenia-go/internal/model"
	"malenia-go/internal/pool"
)

// Syncer 负责把 IpSource 的资源装载进对应的 pool
type Syncer struct {
	db      *gorm.DB
	pools   *pool.Manager
	client  *http.Client
	mu      sync.Mutex
	cancels map[uint]chan struct{} // api 源的停止信号
}

func NewSyncer(db *gorm.DB, pools *pool.Manager) *Syncer {
	return &Syncer{
		db:      db,
		pools:   pools,
		client:  &http.Client{Timeout: 15 * time.Second},
		cancels: map[uint]chan struct{}{},
	}
}

// SyncStatic 从 IpItem 表装载 static 源
func (s *Syncer) SyncStatic(source *model.IpSource) error {
	var items []model.IpItem
	if err := s.db.Where("source_id = ?", source.ID).Find(&items).Error; err != nil {
		return err
	}
	entries := make([]*pool.Entry, 0, len(items))
	for _, it := range items {
		proto := it.Protocol
		if proto == "" {
			proto = source.Protocol
		}
		e := &pool.Entry{
			Key:      entryKey(proto, it.User, it.Host, it.Port),
			Host:     it.Host,
			Port:     it.Port,
			Protocol: proto,
			User:     it.User,
			Pass:     it.Pass,
			Country:  firstNonEmpty(it.Country, source.Country),
			City:     firstNonEmpty(it.City, source.City),
			Lng:      firstNZ(it.Lng, source.Lng),
			Lat:      firstNZ(it.Lat, source.Lat),
		}
		entries = append(entries, e)
	}
	p := s.pools.Get(source.ID)
	p.ReplaceAll(entries, source.PoolSize)
	log.Printf("[ipres] 源[%s] static 装载 %d 条资源", source.Name, len(entries))
	return nil
}

// SyncAPI 抓取一次 api 源并替换池内容
func (s *Syncer) SyncAPI(source *model.IpSource) error {
	now := time.Now()
	err := s.fetchAPI(source)

	finish := func(syncErr string) {
		updates := map[string]interface{}{"last_sync_at": now, "last_sync_err": syncErr}
		s.db.Model(&model.IpSource{}).Where("id = ?", source.ID).Updates(updates)
	}
	if err != nil {
		finish(err.Error())
		return err
	}
	finish("")
	return nil
}

func (s *Syncer) fetchAPI(source *model.IpSource) error {
	if strings.TrimSpace(source.URL) == "" {
		return fmt.Errorf("api source url empty")
	}
	resp, err := s.client.Get(source.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http status %d", resp.StatusCode)
	}
	entries := ParseLines(resp.Body, source)
	p := s.pools.Get(source.ID)
	p.ReplaceAll(entries, source.PoolSize)
	log.Printf("[ipres] 源[%s] api 提取 %d 条资源", source.Name, len(entries))
	return nil
}

// ParseLines 解析提取文本。支持行格式：
//
//	ip:port
//	ip:port,country,city
//	ip:port,country,city,lng,lat
//	socks5://user:pass@host:port,country,city   （行内可覆盖协议与账密）
//	# 开头为注释
func ParseLines(r io.Reader, source *model.IpSource) []*pool.Entry {
	var out []*pool.Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e, ok := parseLine(line, source)
		if ok {
			out = append(out, e)
		}
	}
	return out
}

func parseLine(line string, source *model.IpSource) (*pool.Entry, bool) {
	parts := strings.Split(line, ",")
	head := parts[0]

	proto := source.Protocol
	user, pass := source.UpstreamUser, source.UpstreamPass

	// 行内协议前缀: socks5://user:pass@host:port
	if i := strings.Index(head, "://"); i > 0 {
		scheme := strings.ToLower(head[:i])
		if scheme == model.ProtoHTTP || scheme == model.ProtoSocks5 {
			proto = scheme
			rest := head[i+3:]
			if j := strings.Index(rest, "@"); j > 0 {
				userinfo := rest[:j]
				rest = rest[j+1:]
				if k := strings.Index(userinfo, ":"); k > 0 {
					user, _ = url.QueryUnescape(userinfo[:k])
					pass, _ = url.QueryUnescape(userinfo[k+1:])
				}
			}
			head = rest
		}
	}

	host, portStr, err := splitHostPort(head)
	if err != nil || host == "" {
		return nil, false
	}
	// 纯数字点分 host 必须是合法 IPv4（拒绝 "1.2:99" 这类残缺行）
	if looksNumeric(host) && !validIPv4(host) {
		return nil, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, false
	}

	e := &pool.Entry{
		Key:      entryKey(proto, user, host, port),
		Host:     host,
		Port:     port,
		Protocol: proto,
		User:     user,
		Pass:     pass,
		Country:  source.Country,
		City:     source.City,
		Lng:      source.Lng,
		Lat:      source.Lat,
	}
	if source.LifetimeSec > 0 {
		e.ExpireAt = time.Now().Add(time.Duration(source.LifetimeSec) * time.Second)
	}
	if len(parts) > 1 && parts[1] != "" {
		e.Country = parts[1]
	}
	if len(parts) > 2 && parts[2] != "" {
		e.City = parts[2]
	}
	if len(parts) > 4 {
		if lng, err1 := strconv.ParseFloat(parts[3], 64); err1 == nil {
			if lat, err2 := strconv.ParseFloat(parts[4], 64); err2 == nil {
				e.Lng, e.Lat = lng, lat
			}
		}
	}
	return e, true
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", fmt.Errorf("bad host:port %q", s)
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), nil
}

// looksNumeric 判断是否纯数字点分形式
func looksNumeric(host string) bool {
	for _, c := range host {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

func validIPv4(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return false
		}
	}
	return true
}

func entryKey(proto, user, host string, port int) string {
	if user != "" {
		return fmt.Sprintf("%s://%s@%s:%d", proto, user, host, port)
	}
	return fmt.Sprintf("%s://%s:%d", proto, host, port)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstNZ(vals ...float64) float64 {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}

// StartAll 启动所有 source 的装载与 api 周期同步协程；返回 stop 信号
func (s *Syncer) StartAll(stop <-chan struct{}) error {
	var sources []model.IpSource
	if err := s.db.Where("status = ?", model.StatusEnabled).Find(&sources).Error; err != nil {
		return err
	}
	for i := range sources {
		s.StartSource(&sources[i], stop)
	}
	return nil
}

// StartSource 装载单个源；api 类型则启动周期抓取循环
func (s *Syncer) StartSource(source *model.IpSource, stop <-chan struct{}) {
	s.mu.Lock()
	if old, ok := s.cancels[source.ID]; ok {
		close(old)
	}
	cancel := make(chan struct{})
	s.cancels[source.ID] = cancel
	s.mu.Unlock()

	switch source.Type {
	case model.SourceStatic:
		if err := s.SyncStatic(source); err != nil {
			log.Printf("[ipres] 源[%s] static 装载失败: %v", source.Name, err)
		}
	case model.SourceAPI:
		if err := s.SyncAPI(source); err != nil {
			log.Printf("[ipres] 源[%s] api 首次提取失败: %v", source.Name, err)
		}
		go s.loop(source, cancel, stop)
	}
}

// StopSource 取消某源的同步协程（管理 API 变更后调用）
func (s *Syncer) StopSource(sourceID uint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.cancels[sourceID]; ok {
		close(c)
		delete(s.cancels, sourceID)
	}
}

func (s *Syncer) loop(source *model.IpSource, cancel, stop <-chan struct{}) {
	interval := time.Duration(source.PollSec) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-cancel:
			return
		case <-stop:
			return
		case <-t.C:
			// 重新从 DB 读取最新配置
			var cur model.IpSource
			if err := s.db.First(&cur, source.ID).Error; err != nil || cur.Status != model.StatusEnabled {
				return
			}
			if err := s.SyncAPI(&cur); err != nil {
				log.Printf("[ipres] 源[%s] api 提取失败: %v", cur.Name, err)
			}
		}
	}
}
