// Package upstream 上游出口拨号：按 IP 资源协议建立到目标站点的连接。
// 对应 malenia 的 outbound/handshark（HandShakerHttps / HandShakerSocks5）
// 与 client 包（HttpClient / Socks5）。
package upstream

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Dial 通过上游代理资源连接目标 targetHost:targetPort。
//
//	proto == direct : 不经过任何上游代理，直接拨号到目标
//	proto == http   : 上游为 http 代理，发送 CONNECT
//	proto == socks5 : 上游为 socks5 代理
func Dial(proto, proxyAddr, proxyUser, proxyPass, target string, timeout time.Duration) (net.Conn, error) {
	switch proto {
	case "direct":
		return net.DialTimeout("tcp", target, timeout)
	case "http":
		return dialHttpProxy(proxyAddr, proxyUser, proxyPass, target, timeout)
	case "socks5":
		var auth *proxy.Auth
		if proxyUser != "" {
			auth = &proxy.Auth{User: proxyUser, Password: proxyPass}
		}
		d, err := proxy.SOCKS5("tcp", proxyAddr, auth, &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, err
		}
		return d.Dial("tcp", target)
	default:
		return nil, fmt.Errorf("unknown upstream protocol: %s", proto)
	}
}

// dialHttpProxy 向 http 代理发送 CONNECT target 并等待 200
func dialHttpProxy(proxyAddr, user, pass, target string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", proxyAddr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if user != "" {
		token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req += "Proxy-Authorization: Basic " + token + "\r\n"
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	line := strings.TrimSpace(statusLine)
	// 校验状态行前缀: "HTTP/1.1 200 ..." 
	if !strings.HasPrefix(line, "HTTP/1.0") && !strings.HasPrefix(line, "HTTP/1.1") {
		_ = conn.Close()
		return nil, fmt.Errorf("bad upstream response: %s", line)
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || parts[1] != "200" {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream CONNECT failed: %s", line)
	}
	// 读掉剩余响应头
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("read CONNECT headers: %w", err)
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
