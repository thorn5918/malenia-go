// Package pool IP 资源池。
// 对应 malenia 的 outbound/IpPool：一个 IpSource 对应一个 Pool，
// 内部维护 4 张索引（与 malenia 一致）：
//
//	一致性哈希环    —— 会话固定出口（session sticky）
//	GeoHash 网格    —— 经纬度就近分配（malenia 用 TreeMap<String,ActiveProxyIp> 二维 GeoHash，此处用网格+欧氏距离近似）
//	行政区域分配    —— country -> city
//	入库顺序环      —— 新旧顺序轮询/最新优先
//
// 以及健康探测（LastErrorsSlot / 池健康检查）与动态下线（DropReason 回调）。
package pool

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"malenia-go/internal/upstream"
)

// DropThreshold 连续失败阈值：达到即动态下线
const DropThreshold = 3

// DropReason 下线原因（对齐 malenia DropReason）
type DropReason string

const (
	DropProbeFailed DropReason = "probe_failed"      // 健康探测失败
	DropConnRefused DropReason = "connect_refused"   // 明确得知 ip 已不可用
	DropExpired     DropReason = "expired"           // 达到最长存活时间
	DropOverflow    DropReason = "overflow"          // 池满被挤出
)

// Entry 池内一条代理 IP 资源
type Entry struct {
	Key      string // 唯一键: proto://user@host:port
	Host     string
	Port     int
	Protocol string // direct | http | socks5
	User     string
	Pass     string
	Country  string
	City     string
	Lng      float64
	Lat      float64

	AddedAt  time.Time
	ExpireAt time.Time // 零值表示不限制

	Fails      int          // 连续失败次数
	LastErrors []string     // 最近错误环形记录（对齐 malenia LastErrorsSlot）
	Success    atomic.Int64 // 握手成功次数
	Assigned   atomic.Int64 // 被分配次数
}

// Addr 返回上游代理地址 host:port
func (e *Entry) Addr() string { return fmt.Sprintf("%s:%d", e.Host, e.Port) }

// Desc 调试用描述（即 Key: proto://user@host:port）
func (e *Entry) Desc() string { return e.Key }

// MarkSuccess 握手成功，清零连续失败计数
func (e *Entry) MarkSuccess() { e.Fails = 0; e.Success.Add(1) }

// MarkFail 记录一次失败；连续失败达到阈值时返回 true 并从池中剔除（动态下线）
func (e *Entry) MarkFail(err error) bool {
	e.Fails++
	msg := fmt.Sprintf("%v", err)
	if len(msg) > 200 {
		msg = msg[:200]
	}
	e.LastErrors = append(e.LastErrors, time.Now().Format("15:04:05 ")+msg)
	if len(e.LastErrors) > 5 {
		e.LastErrors = e.LastErrors[len(e.LastErrors)-5:]
	}
	return e.Fails >= DropThreshold
}

// --------------------------------------------------------------------

// Manager 管理所有 IpSource 对应的池
type Manager struct {
	mu    sync.Mutex
	pools map[uint]*Pool
	hooks Hooks
}

// Hooks 动态下线回调（malenia IpResourceHandler#onProxyIpDrop 的 Go 版对应物）。
// 未来可扩展：VPS 拨号重播、上报外部系统等。
type Hooks struct {
	OnDrop func(sourceID uint, entry *Entry, reason DropReason)
}

func NewManager(hooks Hooks) *Manager {
	return &Manager{pools: map[uint]*Pool{}, hooks: hooks}
}

func (m *Manager) Get(sourceID uint) *Pool {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.pools[sourceID]
	if p == nil {
		p = &Pool{mgr: m, sourceID: sourceID}
		m.pools[sourceID] = p
	}
	return p
}

func (m *Manager) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, p := range m.pools {
		n += p.Size()
	}
	return n
}

// --------------------------------------------------------------------

// Pool 单个 IpSource 的资源池
type Pool struct {
	mu       sync.Mutex
	mgr      *Manager
	sourceID uint
	all      map[string]*Entry
	seq      []*Entry // 按入库时间排序（seq 环）
	rr       int      // seq 轮询游标
	ring     []ringNode
	drop     int64 // 累计下线数量
}

type ringNode struct {
	h uint64
	e *Entry
}

// ReplaceAll 全量替换池内容（static 源入库 / api 源周期提取时调用）
func (p *Pool) ReplaceAll(entries []*Entry, maxCache int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	old := p.all
	p.all = make(map[string]*Entry, len(entries))
	p.seq = p.seq[:0]
	for _, e := range entries {
		if o, ok := old[e.Key]; ok {
			// 保留健康统计，保持入库时间
			e.Fails, e.LastErrors = o.Fails, o.LastErrors
			e.AddedAt = o.AddedAt
			e.Success.Store(o.Success.Load())
			e.Assigned.Store(o.Assigned.Load())
		} else {
			e.AddedAt = now
		}
		p.all[e.Key] = e
		p.seq = append(p.seq, e)
	}
	// 池溢出保护：超出 maxCache 时按入库时间从旧到新挤出（malenia cachedProxies 的教训：
	// 曾因未处理溢出导致内存中滞留两百万条 ip 资源）
	if maxCache > 0 && len(p.seq) > maxCache {
		overflow := len(p.seq) - maxCache
		for i := 0; i < overflow; i++ {
			delete(p.all, p.seq[i].Key)
		}
		p.seq = p.seq[overflow:]
	}
	p.rebuildRingLocked()
}

func (p *Pool) Add(e *Entry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.all == nil {
		p.all = map[string]*Entry{}
	}
	if _, exists := p.all[e.Key]; exists {
		return
	}
	e.AddedAt = time.Now()
	p.all[e.Key] = e
	p.seq = append(p.seq, e)
	p.rebuildRingLocked()
}

func (p *Pool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.all)
}

func (p *Pool) Dropped() int64 { return atomic.LoadInt64(&p.drop) }

func (p *Pool) rebuildRingLocked() {
	const vnodes = 100
	p.ring = make([]ringNode, 0, len(p.all)*vnodes)
	for _, e := range p.all {
		for i := 0; i < vnodes; i++ {
			p.ring = append(p.ring, ringNode{h: hash64(fmt.Sprintf("%s#%d", e.Key, i)), e: e})
		}
	}
	sort.Slice(p.ring, func(i, j int) bool { return p.ring[i].h < p.ring[j].h })
}

// Allocate 按隧道路由参数分配一个出口 IP（核心选路逻辑，对齐 malenia performAllocateIp）:
//  1. lng_lat 参数 -> GeoHash 网格就近分配
//  2. country(/city) 参数 -> 行政区域分配
//  3. 默认 -> 一致性哈希环（相同 session 固定出口）
//  4. 兜底 -> 入库顺序环轮询
//
// exclude 为本轮 failover 已尝试失败的 IP 键集合。
func (p *Pool) Allocate(params map[string]string, hash uint64, exclude map[string]bool) *Entry {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 1. 经纬度就近
	if v := params["lng_lat"]; v != "" {
		if lng, lat, ok := parseLL(v); ok {
			if e := p.pickGeoLocked(lng, lat, exclude); e != nil {
				e.Assigned.Add(1)
				return e
			}
		}
	}

	// 2. 行政区域
	if country := params["country"]; country != "" {
		city := params["city"]
		if e := p.pickAdminLocked(country, city, hash, exclude); e != nil {
			e.Assigned.Add(1)
			return e
		}
	}

	// 3. 一致性哈希（session sticky）
	if e := p.pickRingLocked(hash, exclude); e != nil {
		e.Assigned.Add(1)
		return e
	}

	// 4. 兜底：顺序环轮询
	if e := p.pickSeqLocked(exclude); e != nil {
		e.Assigned.Add(1)
		return e
	}
	return nil
}

// pickGeoLocked 经纬度就近分配：
// 以 0.01 度网格（约 1km）聚合，检索目标附近 ±3 格，欧氏距离最近者胜出。
// 近似 malenia 的二维 GeoHash TreeMap 最近匹配。
func (p *Pool) pickGeoLocked(lng, lat float64, exclude map[string]bool) *Entry {
	grid := map[[2]int][]*Entry{}
	for _, e := range p.all {
		if e.Lng == 0 && e.Lat == 0 {
			continue
		}
		k := [2]int{int(lngKey(e.Lng)), int(latKey(e.Lat))}
		grid[k] = append(grid[k], e)
	}
	tl, ta := int(lngKey(lng)), int(latKey(lat))
	var bestEntry *Entry
	bestDist := -1.0
	for dx := -3; dx <= 3; dx++ {
		for dy := -3; dy <= 3; dy++ {
			for _, e := range grid[[2]int{tl + dx, ta + dy}] {
				if exclude[e.Key] {
					continue
				}
				d := dist(e.Lng, e.Lat, lng, lat)
				if bestDist < 0 || d < bestDist {
					bestDist = d
					bestEntry = e
				}
			}
		}
	}
	return bestEntry
}

func (p *Pool) pickAdminLocked(country, city string, hash uint64, exclude map[string]bool) *Entry {
	var cands []*Entry
	for _, e := range p.all {
		if e.Country != country || exclude[e.Key] {
			continue
		}
		if city != "" && e.City != city {
			continue
		}
		cands = append(cands, e)
	}
	if len(cands) == 0 {
		return nil
	}
	return cands[hash%uint64(len(cands))]
}

func (p *Pool) pickRingLocked(hash uint64, exclude map[string]bool) *Entry {
	n := len(p.ring)
	if n == 0 {
		return nil
	}
	idx := sort.Search(n, func(i int) bool { return p.ring[i].h >= hash })
	for i := 0; i < n; i++ {
		node := p.ring[(idx+i)%n]
		if !exclude[node.e.Key] {
			return node.e
		}
	}
	return nil
}

func (p *Pool) pickSeqLocked(exclude map[string]bool) *Entry {
	n := len(p.seq)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		e := p.seq[(p.rr+i)%n]
		if !exclude[e.Key] {
			p.rr = (p.rr + i + 1) % n
			return e
		}
	}
	return nil
}

// Remove 剔除一个 IP（动态下线）
func (p *Pool) Remove(e *Entry, reason DropReason) {
	p.mu.Lock()
	if _, ok := p.all[e.Key]; !ok {
		p.mu.Unlock()
		return
	}
	delete(p.all, e.Key)
	for i, s := range p.seq {
		if s.Key == e.Key {
			p.seq = append(p.seq[:i], p.seq[i+1:]...)
			break
		}
	}
	atomic.AddInt64(&p.drop, 1)
	sourceID := p.sourceID
	p.rebuildRingLocked()
	p.mu.Unlock()

	if p.mgr != nil && p.mgr.hooks.OnDrop != nil {
		p.mgr.hooks.OnDrop(sourceID, e, reason)
	}
}

func (p *Pool) sourceIDLocked() uint { return p.sourceID }

// Snapshot 池内条目快照（管理 API 用）
func (p *Pool) Snapshot() []*Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*Entry, 0, len(p.all))
	for _, e := range p.seq {
		out = append(out, e)
	}
	return out
}

// ProbeOnce 对池内所有存活条目执行一轮健康探测：
// 通过各出口向 probeTarget(如 1.1.1.1:80) 发起 TCP 连接，超时 5s。
// 探测失败累计达到 DropThreshold 即动态下线（原因 DropProbeFailed）；
// 到达 ExpireAt 的条目直接以 DropExpired 下线。
func (p *Pool) ProbeOnce(sourceID uint, probeTarget string) {
	now := time.Now()
	snapshot := func() []*Entry {
		p.mu.Lock()
		defer p.mu.Unlock()
		var out []*Entry
		for _, e := range p.all {
			if !e.ExpireAt.IsZero() && now.After(e.ExpireAt) {
				continue // 过期单独处理
			}
			out = append(out, e)
		}
		return out
	}()

	var wg sync.WaitGroup
	for _, e := range snapshot {
		e := e
		if !e.ExpireAt.IsZero() && now.After(e.ExpireAt) {
			p.Remove(e, DropExpired)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := upstream.Dial(e.Protocol, e.Addr(), e.User, e.Pass, probeTarget, 5*time.Second)
			if conn != nil {
				_ = conn.Close()
			}
			if err != nil {
				if e.MarkFail(err) {
					p.Remove(e, DropProbeFailed)
				}
				return
			}
			e.MarkSuccess()
		}()
	}
	wg.Wait()
}

// ---- helpers ----

func hash64(s string) uint64 {
	var h uint64 = 14695981039346656037 // FNV-1a
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return avalanche(h)
}

// avalanche murmur3 finalizer：补强 FNV 对相似输入的雪崩效应，
// 避免哈希环上落点聚簇（session 分散度）
func avalanche(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

func parseLL(v string) (float64, float64, bool) {
	parts := strings.SplitN(v, "_", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	var lng, lat float64
	if _, err := fmt.Sscanf(parts[0], "%f", &lng); err != nil {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(parts[1], "%f", &lat); err != nil {
		return 0, 0, false
	}
	return lng, lat, true
}

func lngKey(v float64) float64 { return float64(int(v*100)) / 100 }
func latKey(v float64) float64 { return float64(int(v*100)) / 100 }

func dist(x1, y1, x2, y2 float64) float64 {
	dx, dy := x1-x2, y1-y2
	return dx*dx + dy*dy
}
