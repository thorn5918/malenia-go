package auth

import (
	"math"
	"strconv"
	"strings"
)

func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(s), 64)
}

// Whitelist CIDR 白名单。Match 返回命中的 userID。
// malenia 用 IpTrie 做大规模前缀匹配；这里用户白名单条目有限，采用线性匹配即可。
type Whitelist struct {
	entries []whiteEntry
}

type whiteEntry struct {
	userID uint
	ipNet  cidr
}

type cidr struct {
	ip   uint32
	mask uint32
}

// NewWhitelist 由 (userID, cidrStr) 列表构建，非法条目忽略
func NewWhitelist(items []struct {
	UserID uint
	CIDR   string
}) *Whitelist {
	w := &Whitelist{}
	for _, it := range items {
		if c, ok := parseCIDR(it.CIDR); ok {
			w.entries = append(w.entries, whiteEntry{userID: it.UserID, ipNet: c})
		}
	}
	return w
}

// Match 返回命中白名单的用户 id（未命中返回 0）
func (w *Whitelist) Match(ipStr string) uint {
	ip, ok := parseIP(ipStr)
	if !ok {
		return 0
	}
	for _, e := range w.entries {
		if (ip & e.ipNet.mask) == e.ipNet.ip {
			return e.userID
		}
	}
	return 0
}

func (w *Whitelist) Len() int { return len(w.entries) }

// ---- 简易 ipv4 解析（白名单场景足以，不支持 ipv6 时条目被忽略） ----

func parseCIDR(s string) (cidr, bool) {
	s = strings.TrimSpace(s)
	idx := strings.IndexByte(s, '/')
	if idx <= 0 {
		ip, ok := parseIP(s)
		if !ok {
			return cidr{}, false
		}
		return cidr{ip: ip, mask: 0xffffffff}, true
	}
	ip, ok := parseIP(s[:idx])
	if !ok {
		return cidr{}, false
	}
	bits, err := strconv.Atoi(s[idx+1:])
	if err != nil || bits < 0 || bits > 32 {
		return cidr{}, false
	}
	var mask uint32
	if bits == 0 {
		mask = 0
	} else {
		mask = uint32(math.MaxUint32 << (32 - bits)) //nolint
	}
	return cidr{ip: ip & mask, mask: mask}, true
}

func parseIP(s string) (uint32, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0, false
	}
	var ip uint32
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return 0, false
		}
		ip = ip<<8 | uint32(v)
	}
	return ip, true
}
