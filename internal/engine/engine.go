// Package engine 代理会话引擎：认证 -> 出口分配 -> 上游拨号 -> 会话结束。
// 对应 malenia 的 Session + WrapperOrder(鉴权/限流) + WrapperProduct#allocateIp
// + switcher/OutboundConnectTask(failover 换 IP 重试)。
package engine

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"malenia-go/internal/auth"
	"malenia-go/internal/ipres"
	"malenia-go/internal/metric"
	"malenia-go/internal/model"
	"malenia-go/internal/pool"
	"malenia-go/internal/record"
	"malenia-go/internal/relay"
	"malenia-go/internal/upstream"
)

// SessionCtx 一次代理会话的上下文（malenia Session 的 Go 版）
type Ctx struct {
	SessionID string
	User      model.UserInfo
	Order     model.UserOrder
	Product   model.Product
	Params    map[string]string // 隧道路由参数
	RemoteIP  string
	Protocol  string // 客户端接入协议: http | socks5
	Target    string // 目标 host:port
	Begin     time.Time
}

type OrderMeter struct {
	Upload   atomic.Int64
	Download atomic.Int64
	Active   atomic.Int32
}

type sourceRef struct {
	Source model.IpSource
	Weight int
}

// Engine 会话引擎
type Engine struct {
	db      *gorm.DB
	pools   *pool.Manager
	syncer  *ipres.Syncer
	records *record.Writer

	mu       sync.Mutex
	meters   map[uint]*OrderMeter
	limiters map[uint]*relay.BandwidthLimiter
	sources  map[uint][]sourceRef // productID -> sources（Reload 后缓存）

	wlMu       sync.Mutex
	whitelist  *auth.Whitelist
	wlLoadTime time.Time
}

func New(db *gorm.DB, pools *pool.Manager, syncer *ipres.Syncer, records *record.Writer) *Engine {
	return &Engine{
		db:       db,
		pools:    pools,
		syncer:   syncer,
		records:  records,
		meters:   map[uint]*OrderMeter{},
		limiters: map[uint]*relay.BandwidthLimiter{},
		sources:  map[uint][]sourceRef{},
	}
}

// Reload 重载产品-源绑定缓存与白名单（管理端变更后调用）
func (e *Engine) Reload() {
	var rows []model.ProductSource
	if err := e.db.Find(&rows).Error; err != nil {
		log.Printf("[engine] reload product sources failed: %v", err)
		return
	}
	var sources []model.IpSource
	if err := e.db.Where("status = ?", model.StatusEnabled).Find(&sources).Error; err != nil {
		return
	}
	srcMap := map[uint]model.IpSource{}
	for _, s := range sources {
		srcMap[s.ID] = s
	}
	ns := map[uint][]sourceRef{}
	for _, r := range rows {
		if s, ok := srcMap[r.SourceID]; ok {
			w := r.Weight
			if w <= 0 {
				w = 1
			}
			ns[r.ProductID] = append(ns[r.ProductID], sourceRef{Source: s, Weight: w})
		}
	}
	e.mu.Lock()
	e.sources = ns
	e.mu.Unlock()

	e.wlMu.Lock()
	e.wlLoadTime = time.Time{}
	e.wlMu.Unlock()
}

// ------------------------------------------------------------------
// 鉴权
// ------------------------------------------------------------------

var (
	ErrAuthRequired   = errors.New("需要代理账密或白名单授权")
	ErrAuthBad        = errors.New("代理账密错误")
	ErrOrderSuspended = errors.New("订单已停用或已过期")
	ErrNoBalance      = errors.New("账户余额不足")
	ErrOrderNotFound  = errors.New("未找到该产品的有效订单")
	ErrTooManyConns   = errors.New("并发连接数超限")
)

// Authenticate 代理层鉴权。
// authUser 可能携带隧道路由参数（用户-参数-值 格式）；
// authUser 为空时尝试 IP 白名单（malenia 白名单鉴权路径）。
func (e *Engine) Authenticate(product *model.Product, remoteIP, authUser, authPass, proto string) (*Ctx, error) {
	username, params := auth.ParseTunnelParams(authUser)

	var order model.UserOrder
	if username != "" {
		if err := e.db.Where("proxy_username = ? AND product_id = ?", username, product.ID).
			First(&order).Error; err != nil {
			metric.AuthFailed.Add(1)
			return nil, ErrAuthBad
		}
		if order.ProxyPassword != authPass {
			metric.AuthFailed.Add(1)
			return nil, ErrAuthBad
		}
	} else {
		userID := e.matchWhitelist(remoteIP)
		if userID == 0 {
			metric.AuthFailed.Add(1)
			return nil, ErrAuthRequired
		}
		if err := e.db.Where("user_id = ? AND product_id = ? AND status = ?",
			userID, product.ID, model.StatusEnabled).First(&order).Error; err != nil {
			metric.AuthFailed.Add(1)
			return nil, ErrOrderNotFound
		}
	}

	// 订单状态
	now := time.Now()
	if order.Status != model.StatusEnabled || (order.ExpireAt != nil && order.ExpireAt.Before(now)) {
		metric.AuthFailed.Add(1)
		return nil, ErrOrderSuspended
	}

	// 用户状态与余额（预充值模式：余额 <=0 拒绝）
	var user model.UserInfo
	if err := e.db.First(&user, order.UserID).Error; err != nil {
		metric.AuthFailed.Add(1)
		return nil, ErrAuthBad
	}
	if user.Status != model.StatusEnabled {
		metric.AuthFailed.Add(1)
		return nil, ErrOrderSuspended
	}
	switch product.BillingType {
	case model.BillingTraffic, model.BillingDuration:
		if user.Balance <= 0 {
			metric.AuthFailed.Add(1)
			return nil, ErrNoBalance
		}
	case model.BillingCount:
		if user.Balance < product.PricePerReq {
			metric.AuthFailed.Add(1)
			return nil, ErrNoBalance
		}
	}

	// 按次计费：请求时扣费
	if product.BillingType == model.BillingCount && product.PricePerReq > 0 {
		e.deductBalance(user.ID, product.PricePerReq)
	}

	// 并发限制
	m := e.meter(order.ID)
	if order.Concurrency > 0 {
		if cur := m.Active.Add(1); int(cur) > order.Concurrency {
			m.Active.Add(-1)
			metric.AuthFailed.Add(1)
			return nil, ErrTooManyConns
		}
	} else {
		m.Active.Add(1)
	}

	metric.AuthOK.Add(1)
	ctx := &Ctx{
		SessionID: newSessionID(),
		User:      user,
		Order:     order,
		Product:   *product,
		Params:    params,
		RemoteIP:  remoteIP,
		Protocol:  proto,
		Begin:     now,
	}

	// trace_id：会话追踪日志（malenia USER_DEBUG_TRACE 的极简版）
	if t := params["trace_id"]; t != "" {
		log.Printf("[trace:%s] 会话建立 user=%s order=%d proto=%s remote=%s params=%v",
			t, user.Username, order.ID, proto, remoteIP, params)
	}
	return ctx, nil
}

// MatchWhitelist 返回命中白名单的用户 id
func (e *Engine) MatchWhitelist(remoteIP string) uint {
	return e.matchWhitelist(remoteIP)
}

// AuthenticateByWhitelist 白名单免账密鉴权入口（socks5 无鉴权协商路径）
func (e *Engine) AuthenticateByWhitelist(product *model.Product, remoteIP, proto string) (*Ctx, error) {
	return e.Authenticate(product, remoteIP, "", "", proto)
}

// matchWhitelist 返回命中白名单的用户 id
func (e *Engine) matchWhitelist(remoteIP string) uint {
	e.wlMu.Lock()
	if e.whitelist == nil || time.Since(e.wlLoadTime) > 30*time.Second {
		var rows []model.AuthWhiteIp
		if err := e.db.Find(&rows).Error; err == nil {
			items := make([]struct {
				UserID uint
				CIDR   string
			}, 0, len(rows))
			for _, r := range rows {
				items = append(items, struct {
					UserID uint
					CIDR   string
				}{r.UserID, r.CIDR})
			}
			e.whitelist = auth.NewWhitelist(items)
			e.wlLoadTime = time.Now()
		}
	}
	wl := e.whitelist
	e.wlMu.Unlock()
	if wl == nil {
		return 0
	}
	return wl.Match(remoteIP)
}

// ------------------------------------------------------------------
// 出口分配与上游拨号（failover）
// ------------------------------------------------------------------

// AllocateAndDial 分配出口 IP 并建立上游连接。
// failover：隧道建立失败时换 IP 重试（malenia 的 failover 语义，重试无状态，
// 成功的 ip 会成为该路由 session 的固定 ip —— Go 版通过 session hash 环实现粘性）。
func (e *Engine) AllocateAndDial(ctx *Ctx, targetHost, targetPort string) (net.Conn, *pool.Entry, error) {
	timeout := time.Duration(ctx.Product.ConnectTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	attempts := ctx.Order.FailoverCount
	if attempts <= 0 {
		attempts = ctx.Product.FailoverCount
	}
	if attempts <= 0 {
		attempts = 3
	}
	target := targetHost + ":" + targetPort
	ctx.Target = target
	hash := e.sessionHash(ctx)
	exclude := map[string]bool{}

	var lastErr error
	for i := 0; i < attempts; i++ {
		entry, sourceID := e.allocate(ctx, hash, exclude)
		if entry == nil {
			lastErr = errors.New("无可用的出口 ip 资源")
			break
		}
		conn, err := upstream.Dial(entry.Protocol, entry.Addr(), entry.User, entry.Pass, target, timeout)
		if err != nil {
			log.Printf("[session %s] 出口 %s 拨号失败: %v", ctx.SessionID, entry.Desc(), err)
			if entry.MarkFail(err) {
				e.pools.Get(sourceID).Remove(entry, pool.DropConnRefused)
			}
			exclude[entry.Key] = true
			metric.AllocFail.Add(1)
			lastErr = err
			continue
		}
		entry.MarkSuccess()
		if t := ctx.Params["trace_id"]; t != "" {
			log.Printf("[trace:%s] 出口选择 %s -> %s", t, entry.Desc(), target)
		}
		return conn, entry, nil
	}
	metric.AllocFail.Add(1)
	return nil, nil, fmt.Errorf("failover %d 次后仍失败: %w", attempts, lastErr)
}

// allocate 选取出口：先选源（加权随机/偏好参数），再从源池分配 ip；
// 返回 (出口条目, 来源源 id)；direct 源池为空时合成直连出口（便于本地联调）。
func (e *Engine) allocate(ctx *Ctx, hash uint64, exclude map[string]bool) (*pool.Entry, uint) {
	source := e.pickSource(ctx)
	if source == nil {
		return nil, 0
	}
	p := e.pools.Get(source.ID)
	if e := p.Allocate(ctx.Params, hash, exclude); e != nil {
		return e, source.ID
	}
	// direct 源：池中无需真实 ip 条目，合成一条直连出口
	if source.Protocol == model.ProtoDirect && p.Size() == 0 {
		return &pool.Entry{Key: "direct://local", Host: "direct", Protocol: model.ProtoDirect}, source.ID
	}
	return nil, source.ID
}

// pickSource 加权随机选源；支持 outbound_prefer_ip_source 路由参数
func (e *Engine) pickSource(ctx *Ctx) *model.IpSource {
	e.mu.Lock()
	refs := e.sources[ctx.Product.ID]
	e.mu.Unlock()
	if len(refs) == 0 {
		return nil
	}
	if prefer := ctx.Params["outbound_prefer_ip_source"]; prefer != "" {
		for i := range refs {
			if refs[i].Source.Name == prefer {
				return &refs[i].Source
			}
		}
	}
	total := 0
	for i := range refs {
		total += refs[i].Weight
	}
	n := rand.Intn(total)
	for i := range refs {
		n -= refs[i].Weight
		if n < 0 {
			return &refs[i].Source
		}
	}
	return &refs[0].Source
}

// sessionHash 会话哈希：session_id 参数 > 随机隧道(每请求随机) > 会话 UUID。
// 决定一致性哈希环上的落点，从而实现"相同会话固定出口"。
func (e *Engine) sessionHash(ctx *Ctx) uint64 {
	if sid := ctx.Params["session_id"]; sid != "" {
		return fnv64(sid)
	}
	if ctx.Order.RandomTurning {
		return fnv64(newSessionID())
	}
	return fnv64(ctx.SessionID)
}

// ------------------------------------------------------------------
// 会话结束、计量与计费
// ------------------------------------------------------------------

// SessionEnd 会话结束：累计流量、扣减并发、写访问记录
func (e *Engine) SessionEnd(ctx *Ctx, upload, download int64, status, errMsg string) {
	m := e.meter(ctx.Order.ID)
	m.Upload.Add(upload)
	m.Download.Add(download)
	m.Active.Add(-1)

	metric.BytesUp.Add(upload)
	metric.BytesDown.Add(download)

	if t := ctx.Params["trace_id"]; t != "" {
		log.Printf("[trace:%s] 会话结束 up=%d down=%d status=%s", t, upload, download, status)
	}
	e.records.Submit(&model.AccessRecord{
		SessionID:     ctx.SessionID,
		UserID:        ctx.User.ID,
		OrderID:       ctx.Order.ID,
		ProductID:     ctx.Product.ID,
		Protocol:      ctx.Protocol,
		TargetHost:    ctx.Target,
		BeginAt:       ctx.Begin,
		EndAt:         time.Now(),
		UploadBytes:   upload,
		DownloadBytes: download,
		Status:        status,
		ErrMsg:        errMsg,
	})
}

func (e *Engine) meter(orderID uint) *OrderMeter {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := e.meters[orderID]
	if m == nil {
		m = &OrderMeter{}
		e.meters[orderID] = m
	}
	return m
}

// Limiter 订单级带宽限流器（同一订单所有会话共享配额）
func (e *Engine) Limiter(orderID uint, bandwidthKBps int) *relay.BandwidthLimiter {
	e.mu.Lock()
	defer e.mu.Unlock()
	l := e.limiters[orderID]
	if l == nil {
		l = relay.NewBandwidthLimiter(bandwidthKBps)
		e.limiters[orderID] = l
	}
	return l
}

// FlushLoop 周期性把内存计量数据刷入数据库并执行实时扣费
func (e *Engine) FlushLoop(stop <-chan struct{}) {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				e.flushOnce()
			}
		}
	}()
}

func (e *Engine) flushOnce() {
	e.mu.Lock()
	meters := make(map[uint]*OrderMeter, len(e.meters))
	for k, v := range e.meters {
		meters[k] = v
	}
	e.mu.Unlock()

	for orderID, m := range meters {
		up := m.Upload.Swap(0)
		down := m.Download.Swap(0)
		if up+down == 0 {
			continue
		}
		var order model.UserOrder
		if err := e.db.First(&order, orderID).Error; err != nil {
			continue
		}
		var product model.Product
		if err := e.db.First(&product, order.ProductID).Error; err != nil {
			continue
		}
		e.db.Model(&model.UserOrder{}).Where("id = ?", order.ID).
			UpdateColumn("used_bytes", gorm.Expr("used_bytes + ?", up+down))
		e.db.Model(&model.UserOrder{}).Where("id = ?", order.ID).
			UpdateColumn("used_count", gorm.Expr("used_count + ?", 1))

		if product.BillingType == model.BillingTraffic && product.PricePerGB > 0 {
			amount := float64(up+down) / 1e9 * product.PricePerGB
			e.deductBalance(order.UserID, amount)
		}
	}
}

func (e *Engine) deductBalance(userID uint, amount float64) {
	e.db.Model(&model.UserInfo{}).Where("id = ?", userID).
		UpdateColumn("balance", gorm.Expr("balance - ?", amount))
}

// HourlyBilling 按小时计费作业（malenia：每小时扣费直到余额耗尽）
func (e *Engine) HourlyBilling(stop <-chan struct{}) {
	go func() {
		t := time.NewTicker(1 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				var orders []model.UserOrder
				e.db.Where("status = ?", model.StatusEnabled).Find(&orders)
				for _, o := range orders {
					var product model.Product
					if err := e.db.First(&product, o.ProductID).Error; err != nil {
						continue
					}
					if product.BillingType != model.BillingDuration || product.PricePerHour <= 0 {
						continue
					}
					e.deductBalance(o.UserID, product.PricePerHour)
					// 余额耗尽 -> 订单自动停用
					var user model.UserInfo
					if err := e.db.First(&user, o.UserID).Error; err == nil {
						if user.Balance <= 0 {
							e.db.Model(&model.UserOrder{}).Where("id = ?", o.ID).
								UpdateColumn("status", model.StatusDisabled)
							log.Printf("[billing] 用户 %s 余额耗尽，订单 %d 自动停用", user.Username, o.ID)
						}
					}
				}
			}
		}
	}()
}

// ---- utils ----

func fnv64(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	// murmur3 finalizer，补强雪崩（与 pool.hash64 一致）
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

func newSessionID() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(rand.Int31())
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
