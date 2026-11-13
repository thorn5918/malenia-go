package ipres

import (
	"strings"
	"testing"

	"malenia-go/internal/model"
)

func TestParseLines(t *testing.T) {
	src := &model.IpSource{Protocol: model.ProtoSocks5, Country: "cn", City: "hz"}
	text := `# 注释
1.2.3.4:8080
5.6.7.8:1080,us,la
9.9.9.9:9999,jp,tkyo,139.7,35.6
http://a:b@10.0.0.1:3128,cn,sh
badline
1.2.3:99`

	entries := ParseLines(strings.NewReader(text), src)
	if len(entries) != 4 {
		t.Fatalf("解析条目数 = %d, 期望 4: %v", len(entries), entries)
	}
	e0 := entries[0]
	if e0.Host != "1.2.3.4" || e0.Port != 8080 || e0.Protocol != model.ProtoSocks5 || e0.Country != "cn" {
		t.Errorf("entry0 = %+v", e0)
	}
	e1 := entries[1]
	if e1.Country != "us" || e1.City != "la" {
		t.Errorf("entry1 = %+v", e1)
	}
	e2 := entries[2]
	if e2.Lng != 139.7 || e2.Lat != 35.6 || e2.Country != "jp" {
		t.Errorf("entry2 = %+v", e2)
	}
	e3 := entries[3]
	if e3.Protocol != model.ProtoHTTP || e3.User != "a" || e3.Pass != "b" {
		t.Errorf("entry3 = %+v", e3)
	}
}
