// Package relay 双向数据转发 + 订单带宽限流。
// 对应 malenia 的 handlers/RelayHandler + NettyUtil.replay，
// 以及 WrapperOrder#configureRateLimiter 的带宽限制能力。
package relay

import (
	"net"
	"sync"
	"time"
)

// IdleTimeout 数据转发通道空闲超时：10 分钟无流量判定死链并关闭（与 malenia 一致）
const IdleTimeout = 10 * time.Minute

// BandwidthLimiter 简单令牌桶限流器，rate 为每秒允许字节数（0 表示不限）。
// 一个订单共享一个 limiter 实例（订单级带宽限制）。
type BandwidthLimiter struct {
	mu     sync.Mutex
	rate   int64
	tokens float64
	last   time.Time
}

func NewBandwidthLimiter(rateKBps int) *BandwidthLimiter {
	return &BandwidthLimiter{
		rate: int64(rateKBps) * 1024,
		last: time.Now(),
	}
}

func (l *BandwidthLimiter) Rate() int64 {
	if l == nil {
		return 0
	}
	return l.rate
}

// Wait 阻塞直到获得 n 字节配额
func (l *BandwidthLimiter) Wait(n int64) {
	if l == nil || l.rate <= 0 || n <= 0 {
		return
	}
	for {
		l.mu.Lock()
		now := time.Now()
		l.tokens += float64(now.Sub(l.last).Seconds() * float64(l.rate))
		if l.tokens > float64(l.rate) {
			l.tokens = float64(l.rate)
		}
		l.last = now
		if l.tokens >= float64(n) {
			l.tokens -= float64(n)
			l.mu.Unlock()
			return
		}
		need := float64(n) - l.tokens
		l.mu.Unlock()

		wait := time.Duration(need / float64(l.rate) * float64(time.Second))
		if wait > 200*time.Millisecond {
			wait = 200 * time.Millisecond
		}
		if wait <= 0 {
			wait = time.Millisecond
		}
		time.Sleep(wait)
	}
}

// Relay 双向转发。up 为 上行(client->target) 字节数, down 为 下行 字节数。
// 任一方向出错或空闲超时即关闭两个连接。
func Relay(a, b net.Conn, lim *BandwidthLimiter, up, down *int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); *up = pump(a, b, lim) }()
	go func() { defer wg.Done(); *down = pump(b, a, lim) }()
	wg.Wait()
}

// pump 单向拷贝，返回累计字节数。空闲超时通过读截止时间实现。
func pump(from, to net.Conn, lim *BandwidthLimiter) int64 {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		_ = from.SetReadDeadline(time.Now().Add(IdleTimeout))
		nr, err := from.Read(buf)
		if nr > 0 {
			if lim != nil {
				lim.Wait(int64(nr))
			}
			_ = to.SetWriteDeadline(time.Now().Add(time.Minute))
			if err := writeAll(to, buf[:nr]); err != nil {
				break
			}
			total += int64(nr)
		}
		if err != nil {
			break
		}
	}
	_ = from.Close()
	_ = to.Close()
	return total
}

func writeAll(w net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}
