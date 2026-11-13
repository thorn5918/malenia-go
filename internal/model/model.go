// Package model 定义数据库实体，字段语义与 malenia-open 的实体层对齐：
// UserInfo / Product / UserOrder / IpSource / AccessRecord 等
package model

import "time"

const (
	RoleAdmin = "admin"
	RoleUser  = "user"

	SourceStatic = "static" // IP 资源直接配置在数据库 IpItem 表
	SourceAPI    = "api"    // IP 资源通过 HTTP 接口周期提取

	// 上游出口协议：direct 表示不带上游代理、直接拨号(便于本地联调/自有机房场景)
	ProtoDirect = "direct"
	ProtoHTTP   = "http"
	ProtoSocks5 = "socks5"

	BillingTraffic  = "traffic"  // 按流量计费（元/GB，实时扣费）
	BillingDuration = "duration" // 按小时计费（元/小时，整点扣费）
	BillingCount    = "count"    // 按次计费（元/次）

	StatusEnabled  = 1
	StatusDisabled = 0
)

// UserInfo 后台账户。Balance 为余额（元），预充值模式
type UserInfo struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"uniqueIndex;size:64" json:"username"`
	Password  string    `gorm:"size:128" json:"-"`
	Role      string    `gorm:"size:16;default:user" json:"role"`
	Balance   float64   `gorm:"default:0" json:"balance"`
	Token     string    `gorm:"index;size:64" json:"-"`
	Status    int       `gorm:"default:1" json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

// AuthWhiteIp 用户级 IP 白名单（CIDR），白名单内出口 IP 免账密鉴权
type AuthWhiteIp struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"index" json:"userId"`
	CIDR      string    `gorm:"size:64" json:"cidr"`
	Comment   string    `gorm:"size:128" json:"comment"`
	CreatedAt time.Time `json:"createdAt"`
}

// Product 代理产品：一个产品对应一个服务端口 + 一组 IP 源 + 计费方式
type Product struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	Name              string    `gorm:"uniqueIndex;size:64" json:"name"`
	Description       string    `gorm:"size:256" json:"description"`
	ListenPort        int       `gorm:"uniqueIndex" json:"listenPort"`
	BillingType       string    `gorm:"size:16;default:traffic" json:"billingType"`
	PricePerGB        float64   `gorm:"default:0" json:"pricePerGB"`
	PricePerHour      float64   `gorm:"default:0" json:"pricePerHour"`
	PricePerReq       float64   `gorm:"default:0" json:"pricePerReq"`
	FailoverCount     int       `gorm:"default:3" json:"failoverCount"`
	ConnectTimeoutSec int       `gorm:"default:5" json:"connectTimeoutSec"`
	Status            int       `gorm:"default:1" json:"status"`
	CreatedAt         time.Time `json:"createdAt"`
}

// ProductSource 产品与 IP 源的多对多绑定，Weight 用于加权随机选源
type ProductSource struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	ProductID uint   `gorm:"uniqueIndex:idx_product_source" json:"productId"`
	SourceID  uint   `gorm:"uniqueIndex:idx_product_source" json:"sourceId"`
	Weight    int    `gorm:"default:1" json:"weight"`
}

// UserOrder 用户对产品的订单，承载代理鉴权账密与隧道路由相关配置。
// ProxyUsername 全局唯一，支持隧道路由参数后缀（用户-参数-值 形式）
type UserOrder struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	UserID        uint       `gorm:"uniqueIndex:idx_order_user_product" json:"userId"`
	ProductID     uint       `gorm:"uniqueIndex:idx_order_user_product" json:"productId"`
	ProxyUsername string     `gorm:"uniqueIndex;size:64" json:"proxyUsername"`
	ProxyPassword string     `gorm:"size:64" json:"proxyPassword"`
	RandomTurning bool       `gorm:"default:false" json:"randomTurning"` // 随机隧道：每个请求随机出口
	FailoverCount int        `gorm:"default:3" json:"failoverCount"`     // 0 表示沿用产品配置
	BandwidthKBps int        `gorm:"default:0" json:"bandwidthKBps"`     // 0 表示不限带宽
	Concurrency   int        `gorm:"default:0" json:"concurrency"`       // 0 表示不限并发
	Status        int        `gorm:"default:1" json:"status"`
	ExpireAt      *time.Time `json:"expireAt"`
	UsedBytes     int64      `gorm:"default:0" json:"usedBytes"`
	UsedCount     int64      `gorm:"default:0" json:"usedCount"`
	CreatedAt     time.Time  `json:"createdAt"`
}

// IpSource IP 资源源
type IpSource struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	Name          string     `gorm:"uniqueIndex;size:64" json:"name"`
	Type          string     `gorm:"size:16" json:"type"` // static | api
	URL           string     `gorm:"size:512" json:"url"`
	Protocol      string     `gorm:"size:16;default:http" json:"protocol"` // direct | http | socks5
	UpstreamUser  string     `gorm:"size:64" json:"upstreamUser"`
	UpstreamPass  string     `gorm:"size:64" json:"upstreamPass"`
	Country       string     `gorm:"size:32" json:"country"` // 资源默认地理属性
	City          string     `gorm:"size:64" json:"city"`
	Lng           float64    `json:"lng"`
	Lat           float64    `json:"lat"`
	PollSec       int        `gorm:"default:300" json:"pollSec"`       // api 源提取周期
	PoolSize      int        `gorm:"default:200" json:"poolSize"`      // 池化上限
	LifetimeSec   int        `gorm:"default:0" json:"lifetimeSec"`     // 最长存活时间，0 不限制
	HealthCheck   bool       `gorm:"default:true" json:"healthCheck"`  // 是否开启健康探测
	Status        int        `gorm:"default:1" json:"status"`
	LastSyncAt    *time.Time `json:"lastSyncAt"`
	LastSyncErr   string     `gorm:"size:256" json:"lastSyncErr"`
	CreatedAt     time.Time  `json:"createdAt"`
}

// IpItem static 源的 IP 条目
type IpItem struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	SourceID  uint      `gorm:"index" json:"sourceId"`
	Host      string    `gorm:"size:64" json:"host"`
	Port      int       `json:"port"`
	Protocol  string    `gorm:"size:16" json:"protocol"`
	User      string    `gorm:"size:64" json:"user"`
	Pass      string    `gorm:"size:64" json:"pass"`
	Country   string    `gorm:"size:32" json:"country"`
	City      string    `gorm:"size:64" json:"city"`
	Lng       float64   `json:"lng"`
	Lat       float64   `json:"lat"`
	CreatedAt time.Time `json:"createdAt"`
}

// AccessRecord 访问记录：一次代理隧道会话的完整档案
type AccessRecord struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	SessionID     string    `gorm:"index;size:36" json:"sessionId"`
	UserID        uint      `gorm:"index" json:"userId"`
	OrderID       uint      `json:"orderId"`
	ProductID     uint      `json:"productId"`
	SourceID      uint      `json:"sourceId"`
	ProxyIP       string    `gorm:"size:64" json:"proxyIp"`
	Protocol      string    `gorm:"size:16" json:"protocol"` // 客户端接入协议 http/socks5
	TargetHost    string    `gorm:"size:128" json:"targetHost"`
	BeginAt       time.Time `json:"beginAt"`
	EndAt         time.Time `json:"endAt"`
	UploadBytes   int64     `json:"uploadBytes"`
	DownloadBytes int64     `json:"downloadBytes"`
	Status        string    `gorm:"size:32" json:"status"`
	ErrMsg        string    `gorm:"size:256" json:"errMsg"`
}
