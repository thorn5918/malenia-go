// Package auth 移植 malenia 的鉴权域解析与白名单：
// - ParseTunnelParams 对应 cn.iinti.malenia2.api.ip.resource.SessionParam#parseUserParam
// - Whitelist 对应 service/proxy/auth/IpTrie（此处用 CIDR 线性匹配实现，量级足够）
package auth

import (
	"strings"
)

// ParseTunnelParams 解析鉴权用户名域中的隧道路由参数。
//
// 格式: 用户名-参数名-参数值-参数名-参数值...，分隔符为 '-'，
// 参数值内若包含 '-' 用 '\' 转义（malenia 规范：密码不要使用 '-' 字符）。
//
// 内置参数（与 malenia SessionParam 对齐）:
//
//	session_id      会话 id，相同会话固定出口 ip
//	country         国家，如 cn
//	city            城市（需同时传 country）
//	lng_lat         经纬度，格式 "经度_纬度"，如 116.457_-95.444（负数需转义 \-95.444）
//	trace_id        追踪 id，用于会话日志定位
//	outbound_prefer_ip_source  偏好 ip 源名称
//
// 示例: "demouser-session_id-123456-country-cn" => 用户名 demouser, {session_id:123456, country:cn}
func ParseTunnelParams(input string) (string, map[string]string) {
	params := map[string]string{}
	input = strings.TrimSpace(input)
	if input == "" {
		return "", params
	}

	segs := splitEscaped(input, '-')
	if len(segs) == 0 {
		return "", params
	}
	username := segs[0]
	for i := 1; i+1 < len(segs); i += 2 {
		k := segs[i]
		v := segs[i+1]
		if k != "" && v != "" {
			params[k] = v
		}
	}
	return username, params
}

// splitEscaped 按 sep 分割，支持 '\' 转义: "\-" 与 "\\" 转义为字面值
func splitEscaped(s string, sep byte) []string {
	var segs []string
	var sb strings.Builder
	r := []byte(s)
	for i := 0; i < len(r); i++ {
		c := r[i]
		if c == '\\' && i+1 < len(r) {
			next := r[i+1]
			if next == '-' || next == '\\' {
				sb.WriteByte(next)
				i++
				continue
			}
		}
		if c == sep {
			segs = append(segs, sb.String())
			sb.Reset()
			continue
		}
		sb.WriteByte(c)
	}
	segs = append(segs, sb.String())
	return segs
}

// ParseLngLat 解析 lng_lat 参数值 "lng_lat" 形如 "116.457_-95.444"
func ParseLngLat(v string) (lng, lat float64, ok bool) {
	parts := strings.SplitN(v, "_", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	lng, err1 := parseFloat(parts[0])
	lat, err2 := parseFloat(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return lng, lat, true
}
