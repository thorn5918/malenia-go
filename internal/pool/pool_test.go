package pool

import (
	"fmt"
	"testing"
)

func mkEntries(n int) []*Entry {
	out := make([]*Entry, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &Entry{
			Key:      fmt.Sprintf("http://10.0.0.%d:8080", i),
			Host:     fmt.Sprintf("10.0.0.%d", i),
			Port:     8080,
			Protocol: "http",
		})
	}
	return out
}

func newTestPool(n int) *Pool {
	p := &Pool{mgr: nil, sourceID: 1}
	p.ReplaceAll(mkEntries(n), 100)
	return p
}

// 一致性哈希：相同 hash 稳定命中同一出口；不同 hash 尽量分散
func TestAllocateHashSticky(t *testing.T) {
	p := newTestPool(10)
	first := p.Allocate(map[string]string{}, 42, nil)
	if first == nil {
		t.Fatal("分配失败")
	}
	for i := 0; i < 5; i++ {
		got := p.Allocate(map[string]string{}, 42, nil)
		if got.Key != first.Key {
			t.Fatalf("相同 hash 命中不同出口: %s vs %s", got.Key, first.Key)
		}
	}
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		// 用 FNV 模拟真实 session hash 的取值分布（大数域），而不是 0..19
		h := hash64(fmt.Sprintf("session-%d", i))
		if e := p.Allocate(map[string]string{}, h, nil); e != nil {
			seen[e.Key] = true
		}
	}
	if len(seen) < 5 {
		t.Errorf("哈希分散度不足: 只命中 %d 个不同出口", len(seen))
	}
}

// 国家/城市匹配
func TestAllocateAdmin(t *testing.T) {
	entries := mkEntries(4)
	entries[0].Country, entries[0].City = "cn", "hz"
	entries[1].Country, entries[1].City = "cn", "bj"
	entries[2].Country, entries[2].City = "us", "la"
	entries[3].Country, entries[3].City = "us", "la"
	p := &Pool{sourceID: 1}
	p.ReplaceAll(entries, 100)

	e := p.Allocate(map[string]string{"country": "cn", "city": "bj"}, 0, nil)
	if e == nil || e.City != "bj" {
		t.Errorf("city 匹配失败: %+v", e)
	}
	e = p.Allocate(map[string]string{"country": "cn"}, 0, nil)
	if e == nil || e.Country != "cn" {
		t.Errorf("country 匹配失败: %+v", e)
	}
	// 指定不存在城市应回退
	e = p.Allocate(map[string]string{"country": "cn", "city": "sz"}, 0, nil)
	if e == nil {
		t.Errorf("不存在城市应回退到国家匹配或兜底, got nil")
	}
}

// 经纬度就近
func TestAllocateGeo(t *testing.T) {
	entries := mkEntries(3)
	entries[0].Lng, entries[0].Lat = 116.46, 39.92 // 北京
	entries[1].Lng, entries[1].Lat = 120.15, 30.27 // 杭州
	entries[2].Lng, entries[2].Lat = 121.47, 31.23 // 上海
	p := &Pool{sourceID: 1}
	p.ReplaceAll(entries, 100)

	// 目标点接近上海
	e := p.Allocate(map[string]string{"lng_lat": "121.48_31.25"}, 0, nil)
	if e == nil || e.Host != "10.0.0.2" {
		t.Errorf("就近分配应命中上海, got %+v", e)
	}
	// 目标点接近北京
	e = p.Allocate(map[string]string{"lng_lat": "116.47_39.93"}, 0, nil)
	if e == nil || e.Host != "10.0.0.0" {
		t.Errorf("就近分配应命中北京, got %+v", e)
	}
}

// exclude（failover）与兜底轮询
func TestAllocateExcludeAndFallback(t *testing.T) {
	p := newTestPool(3)
	first := p.Allocate(map[string]string{}, 7, nil)
	second := p.Allocate(map[string]string{}, 7, map[string]bool{first.Key: true})
	if second == nil || second.Key == first.Key {
		t.Errorf("排除已失败出口失败: %s -> %s", first.Key, second.Key)
	}
	// 全部排除 -> nil
	if p.Allocate(map[string]string{}, 7, map[string]bool{
		"http://10.0.0.0:8080": true, "http://10.0.0.1:8080": true, "http://10.0.0.2:8080": true,
	}) != nil {
		t.Errorf("全排除时应返回 nil")
	}
}

// 连续失败达到阈值动态下线（移除由调用方 engine 执行，与实现一致）
func TestMarkFailDrops(t *testing.T) {
	p := newTestPool(2)
	e := p.Allocate(map[string]string{}, 1, nil)
	for i := 0; i < DropThreshold-1; i++ {
		if e.MarkFail(fmt.Errorf("x")) {
			t.Fatal("未达阈值不应下线")
		}
	}
	if !e.MarkFail(fmt.Errorf("final")) {
		t.Fatal("达到阈值应返回 true")
	}
	p.Remove(e, DropConnRefused)
	if p.Size() != 1 {
		t.Errorf("下线后池大小 = %d, 期望 1", p.Size())
	}
	e2 := p.Allocate(map[string]string{}, 1, nil)
	if e2 == nil || e2.Key == e.Key {
		t.Errorf("下线的出口不应再被分配")
	}
	e2.MarkSuccess()
	if e2.Fails != 0 {
		t.Errorf("成功后应清零失败计数")
	}
}

// 池溢出保护
func TestReplaceAllOverflow(t *testing.T) {
	p := &Pool{sourceID: 1}
	p.ReplaceAll(mkEntries(50), 10)
	if p.Size() != 10 {
		t.Errorf("溢出保护后池大小 = %d, 期望 10", p.Size())
	}
}
