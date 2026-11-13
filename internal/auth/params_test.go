package auth

import (
	"testing"
)

func TestParseTunnelParams(t *testing.T) {
	cases := []struct {
		in       string
		user     string
		expected map[string]string
	}{
		{"demouser", "demouser", map[string]string{}},
		{"", "", map[string]string{}},
		{"demouser-session_id-123456", "demouser", map[string]string{"session_id": "123456"}},
		{"demouser-session_id-123456-country-cn", "demouser", map[string]string{"session_id": "123456", "country": "cn"}},
		{"foo-country-cn-city-北京", "foo", map[string]string{"country": "cn", "city": "北京"}},
		{"foo-lng_lat-116.457_-95.444", "foo", map[string]string{"lng_lat": "116.457_"}},
		// 未转义的负数会被 '-' 分隔符截断（malenia 同样如此，故文档要求写成 \-95.444）
		// 转义: \- 表示字面 '-'
		{"foo-lng_lat-116.457_\\-95.444", "foo", map[string]string{"lng_lat": "116.457_-95.444"}},
	}
	for _, c := range cases {
		user, params := ParseTunnelParams(c.in)
		if user != c.user {
			t.Errorf("%q: 用户名 = %q, 期望 %q", c.in, user, c.user)
		}
		if len(params) != len(c.expected) {
			t.Errorf("%q: 参数数量 = %v, 期望 %v", c.in, params, c.expected)
			continue
		}
		for k, v := range c.expected {
			if params[k] != v {
				t.Errorf("%q: 参数 %s = %q, 期望 %q", c.in, k, params[k], v)
			}
		}
	}
}

func TestParseLngLat(t *testing.T) {
	lng, lat, ok := ParseLngLat("116.457_-95.444")
	if !ok || lng != 116.457 || lat != -95.444 {
		t.Errorf("got %v %v %v", lng, lat, ok)
	}
}
