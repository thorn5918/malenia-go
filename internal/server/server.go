// Package server 接入层：按产品端口启动监听、协议自动探测、HTTP/SOCKS5 处理。
// 对应 malenia 的 ProxyServer（端口 + 协议探测超时控制）、
// inbound/detector（ProtocolDetector + 各 Matcher）、
// inbound/handlers（ProxyHttpHandler / ProxySocks5Handler / RelayHandler）。
package server

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"malenia-go/internal/engine"
	"malenia-go/internal/metric"
	"malenia-go/internal/model"
	"malenia-go/internal/relay"
)

// DetectTimeout 协议探测超时（malenia: 5s 内识别不了就断开）
const DetectTimeout = 5 * time.Second

// Manager 管理所有产品的监听器
type Manager struct {
	db     *gorm.DB
	engine *engine.Engine

	mu    sync.Mutex
	stopC map[int]chan struct{} // port -> stop
}

func NewManager(db *gorm.DB, eng *engine.Engine) *Manager {
	return &Manager{db: db, engine: eng, stopC: map[int]chan struct{}{}}
}

// Reload 同步监听器与数据库中启用的产品一致（对齐 malenia DbConfigs 配置变更自动生效）
func (m *Manager) Reload() error {
	var products []model.Product
	if err := m.db.Where("status = ?", model.StatusEnabled).Find(&products).Error; err != nil {
		return err
	}
	want := map[int]bool{}
	for _, p := range products {
		want[p.ListenPort] = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for port, stop := range m.stopC {
		if !want[port] {
			close(stop)
			delete(m.stopC, port)
			log.Printf("[server] 端口 %d 监听已停止", port)
		}
	}
	for _, p := range products {
		if _, running := m.stopC[p.ListenPort]; running {
			continue
		}
		stop := make(chan struct{})
		m.stopC[p.ListenPort] = stop
		m.startProduct(p, stop)
	}
	return nil
}

func (m *Manager) startProduct(p model.Product, stop <-chan struct{}) {
	prod := p // 捕获副本
	go func() {
		addr := fmt.Sprintf(":%d", prod.ListenPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("[server] 产品[%s] 监听 %s 失败: %v", prod.Name, addr, err)
			return
		}
		log.Printf("[server] 产品[%s] 开始监听 %s", prod.Name, addr)
		go func() {
			<-stop
			_ = ln.Close()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				log.Printf("[server] accept 失败: %v", err)
				return
			}
			go m.serveConn(conn, &prod)
		}
	}()
}

// serveConn 单连接入口：协议探测（malenia ProtocolDetector 的 Go 版实现）
func (m *Manager) serveConn(conn net.Conn, product *model.Product) {
	metric.Sessions.Add(1)
	defer conn.Close()

	// 探测超时：5s 内识别不了协议就断开
	_ = conn.SetReadDeadline(time.Now().Add(DetectTimeout))
	br := bufio.NewReaderSize(conn, 64*1024)
	head, err := br.Peek(1)
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	switch head[0] {
	case 0x05: // SOCKS5 greeting 首字节固定 0x05
		m.serveSocks5(conn, br, product)
	default:
		m.serveHTTP(conn, br, product)
	}
}

// remoteIP 从 conn 提取客户端 ip
func remoteIP(conn net.Conn) string {
	addr := conn.RemoteAddr().String()
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		return strings.Trim(strings.Trim(addr[:i], "["), "]")
	}
	return addr
}

// ==================================================================
// HTTP / HTTPS(CONNECT) 代理处理
// ==================================================================

func (m *Manager) serveHTTP(conn net.Conn, br *bufio.Reader, product *model.Product) {
	remote := remoteIP(conn)

	// 解析首个请求
	req, err := http.ReadRequest(br)
	if err != nil {
		metric.UnknownProto.Add(1)
		return
	}
	authUser, authPass := parseProxyAuth(req)

	proto := "http"
	if req.Method == "CONNECT" {
		proto = "connect"
	}
	ctx, err := m.engine.Authenticate(product, remote, authUser, authPass, proto)
	if err != nil {
		m.httpReject(conn, req.Method == "CONNECT", err)
		return
	}

	// 确定目标 host/port
	var host, port string
	switch {
	case req.Method == "CONNECT":
		host, port = splitHostPortDefault(req.RequestURI, "443")
	case req.URL.IsAbs() && req.URL.Host != "":
		host, port = splitHostPortDefault(req.URL.Host, "80") // http 代理形式（绝对 URI）
	case req.Host != "":
		host, port = splitHostPortDefault(req.Host, "80") // 网关形式（相对 URI + Host 头）
	default:
		m.httpReject(conn, false, errors.New("无法确定目标地址"))
		return
	}

	// failover 出口拨号
	up, entry, err := m.engine.AllocateAndDial(ctx, host, port)
	if err != nil {
		m.httpReject(conn, req.Method == "CONNECT", err)
		m.engine.SessionEnd(ctx, 0, 0, "failed", err.Error())
		return
	}
	defer up.Close()

	limiter := m.engine.Limiter(ctx.Order.ID, ctx.Order.BandwidthKBps)

	if req.Method == "CONNECT" {
		// HTTPS 代理：回复 200 后进入原始字节双向转发（malenia ProxyHttpsProxyMatcher 路径）
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			m.engine.SessionEnd(ctx, 0, 0, "failed", err.Error())
			return
		}
		var up_, down int64
		relay.Relay(conn, up, limiter, &up_, &down)
		m.engine.SessionEnd(ctx, up_, down, "ok", "")
		return
	}

	// 普通 HTTP：重写请求行（绝对 URI -> 源站 URI），过滤 hop-by-hop 头，
	// 然后整条隧道原始透传 —— 客户端 keep-alive 的后续请求也继续透传，
	// 与 malenia NormalHttpPacketHandler 的原始 relay 语义一致。
	uri := req.URL.RequestURI()
	head := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, uri, host)
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		if lk == "proxy-authorization" || lk == "proxy-connection" || lk == "connection" {
			continue
		}
		for _, v := range vs {
			head += fmt.Sprintf("%s: %s\r\n", k, v)
		}
	}
	head += "X-Forwarded-For: " + remote + "\r\n\r\n"

	if _, err := io.WriteString(up, head); err != nil {
		m.engine.SessionEnd(ctx, 0, 0, "failed", err.Error())
		return
	}
	var up_, down int64
	relay.Relay(conn, up, limiter, &up_, &down)
	m.engine.SessionEnd(ctx, up_, down, "ok", "")
	_ = entry // entry 保留用于日志/后续按出口统计
}

// httpReject HTTP 鉴权/分配失败响应：407 或 502
func (m *Manager) httpReject(conn net.Conn, isConnect bool, err error) {
	if isConnect {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	body := http.StatusText(407) + ": " + err.Error()
	resp := fmt.Sprintf("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"malenia-go\"\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	_, _ = io.WriteString(conn, resp)
}

// parseProxyAuth 解析 Proxy-Authorization Basic 头
func parseProxyAuth(req *http.Request) (user, pass string) {
	h := req.Header.Get("Proxy-Authorization")
	if h == "" {
		return "", ""
	}
	token, ok := strings.CutPrefix(h, "Basic ")
	if !ok {
		return "", ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return "", ""
	}
	u, p, found := strings.Cut(string(raw), ":")
	if !found {
		return u, ""
	}
	return u, p
}

func splitHostPortDefault(s, defPort string) (string, string) {
	s = strings.TrimSpace(s)
	// IPv6 字面量: [::1]:443 或 [::1]（无端口）
	if strings.Contains(s, "]") {
		host := s
		port := defPort
		if i := strings.IndexByte(s, ']'); i > 0 {
			host = strings.Trim(s[:i+1], "[]")
			if i+2 < len(s) && s[i+1] == ':' {
				if p, err := strconv.Atoi(s[i+2:]); err == nil && p > 0 && p <= 65535 {
					port = s[i+2:]
				}
			}
		}
		return host, port
	}
	// IPv4/域名: host:port（冒号数不为 1 时按无端口处理）
	if i := strings.LastIndexByte(s, ':'); i > 0 && strings.Count(s, ":") == 1 {
		if p, err := strconv.Atoi(s[i+1:]); err == nil && p > 0 && p <= 65535 {
			return s[:i], s[i+1:]
		}
	}
	return s, defPort
}

// ==================================================================
// SOCKS5 处理（malenia ProxySocks5Handler 的 Go 版）
// ==================================================================

func (m *Manager) serveSocks5(conn net.Conn, br *bufio.Reader, product *model.Product) {
	remote := remoteIP(conn)

	// 1. greeting: VER NMETHODS METHODS
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	n := int(hdr[1])
	methods := make([]byte, n)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	// 是否支持账密(0x02)与无鉴权(0x00)
	supportUserPass, supportNoAuth := false, false
	for _, mm := range methods {
		if mm == 0x02 {
			supportUserPass = true
		}
		if mm == 0x00 {
			supportNoAuth = true
		}
	}
	if !supportUserPass && !supportNoAuth {
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return
	}

	// 白名单命中则优先无鉴权；否则要求账密
	var ctx *engine.Ctx
	var err error
	if supportNoAuth {
		if uid := m.engine.MatchWhitelist(remote); uid != 0 {
			if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
				return
			}
			ctx, err = m.engine.AuthenticateByWhitelist(product, remote, "socks5")
			if err != nil {
				writeSocks5Reply(conn, 0x01)
				return
			}
		}
	}
	if ctx == nil {
		if !supportUserPass {
			_, _ = conn.Write([]byte{0x05, 0xFF})
			return
		}
		if _, err = conn.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		// 子协商: VER ULEN USER PLEN PASSWD
		ub := make([]byte, 2)
		if _, err := io.ReadFull(br, ub); err != nil || ub[0] != 0x01 {
			return
		}
		user := make([]byte, ub[1])
		if _, err := io.ReadFull(br, user); err != nil {
			return
		}
		// PLEN 为 1 字节
		pb := make([]byte, 1)
		if _, err := io.ReadFull(br, pb); err != nil {
			return
		}
		pass := make([]byte, pb[0])
		if _, err := io.ReadFull(br, pass); err != nil {
			return
		}
		ctx, err = m.engine.Authenticate(product, remote, string(user), string(pass), "socks5")
		if err != nil {
			_, _ = conn.Write([]byte{0x01, 0x01}) // 用户名/密码不匹配
			return
		}
		if _, err = conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	}

	// 2. request: VER CMD RSV ATYP ADDR PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 {
		return
	}
	if req[1] != 0x01 { // 仅支持 CONNECT（BIND/UDP ASSOCIATED 暂不支持）
		writeSocks5Reply(conn, 0x07)
		m.engine.SessionEnd(ctx, 0, 0, "failed", "socks5 命令不支持")
		return
	}
	atyp := req[3]
	var host string
	switch atyp {
	case 0x01: // ipv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 0x04: // ipv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		writeSocks5Reply(conn, 0x08)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])

	up, _, err := m.engine.AllocateAndDial(ctx, host, strconv.Itoa(port))
	if err != nil {
		writeSocks5Reply(conn, 0x05) // connection refused
		m.engine.SessionEnd(ctx, 0, 0, "failed", err.Error())
		return
	}
	defer up.Close()

	if !writeSocks5Reply(conn, 0x00) {
		m.engine.SessionEnd(ctx, 0, 0, "failed", "客户端断开")
		return
	}
	var upB, down int64
	limiter := m.engine.Limiter(ctx.Order.ID, ctx.Order.BandwidthKBps)
	relay.Relay(conn, up, limiter, &upB, &down)
	m.engine.SessionEnd(ctx, upB, down, "ok", "")
}

// writeSocks5Reply 回复 socks5 响应（成功/失败统一绑定 0.0.0.0:0 占位）
func writeSocks5Reply(conn net.Conn, code byte) bool {
	_, err := conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err == nil
}
