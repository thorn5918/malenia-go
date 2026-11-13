// Package metric 轻量级全局指标计数器。
// 对应 malenia 的 Monitor/MetricService 的极简版（原系统为 micrometer + 自研 MQL）
package metric

import (
	"sync"
	"sync/atomic"
)

var (
	mu          sync.Mutex
	counters    = map[string]*atomic.Int64{}
	Sessions    = counter("sessions_total")        // 接入会话总数
	UnknownProto = counter("unknown_protocol")     // 未识别协议
	AuthFailed   = counter("auth_failed")          // 鉴权失败
	AuthOK       = counter("auth_success")         // 鉴权成功
	AllocFail    = counter("allocate_failed")      // 出口分配失败
	BytesUp      = counter("bytes_up")             // 上行流量
	BytesDown    = counter("bytes_down")           // 下行流量
)

func counter(name string) *atomic.Int64 {
	mu.Lock()
	defer mu.Unlock()
	c := &atomic.Int64{}
	counters[name] = c
	return c
}

// Inc 按名字累加（用于动态标签场景的极简封装）
func Inc(name string, n int64) {
	mu.Lock()
	c := counters[name]
	if c == nil {
		c = &atomic.Int64{}
		counters[name] = c
	}
	mu.Unlock()
	c.Add(n)
}

// Snapshot 全部计数快照
func Snapshot() map[string]int64 {
	mu.Lock()
	defer mu.Unlock()
	out := make(map[string]int64, len(counters))
	for k, v := range counters {
		out[k] = v.Load()
	}
	return out
}
