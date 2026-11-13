package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"malenia-go/internal/model"
)

// Open 打开数据库（默认纯 Go 驱动的 sqlite，无需 cgo）
func Open(path string) (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(path+"?_busy_timeout=5000"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
}

// Migrate 建表
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&model.UserInfo{},
		&model.AuthWhiteIp{},
		&model.Product{},
		&model.ProductSource{},
		&model.UserOrder{},
		&model.IpSource{},
		&model.IpItem{},
		&model.AccessRecord{},
	)
}

// HashPassword sha256 摘要
func HashPassword(p string) string {
	h := sha256.Sum256([]byte(p))
	return hex.EncodeToString(h[:])
}

func randToken() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() >> (i % 8 * 8))
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:16])
}

// Seed 初始化演示数据：admin 后台账户、演示用户、演示产品/订单、本机直连 IP 源。
// 仅在对应表为空时执行，可重复启动。
func Seed(db *gorm.DB) error {
	// 管理员
	var adminCnt int64
	db.Model(&model.UserInfo{}).Where("role = ?", model.RoleAdmin).Count(&adminCnt)
	if adminCnt == 0 {
		admin := &model.UserInfo{
			Username: "admin", Password: HashPassword("admin123"),
			Role: model.RoleAdmin, Balance: 100000, Token: randToken(),
		}
		if err := db.Create(admin).Error; err != nil {
			return fmt.Errorf("seed admin: %w", err)
		}
		log.Println("[seed] 创建管理员: admin / admin123")
	}

	// 演示用户
	var demo model.UserInfo
	if err := db.Where("username = ?", "demo").First(&demo).Error; err != nil {
		demo = model.UserInfo{
			Username: "demo", Password: HashPassword("demo123"),
			Role: model.RoleUser, Balance: 100, Token: randToken(),
		}
		if err := db.Create(&demo).Error; err != nil {
			return fmt.Errorf("seed demo user: %w", err)
		}
		log.Println("[seed] 创建演示用户: demo / demo123")
	}

	// 演示 IP 源：direct 协议（不带上游代理，直接拨号），便于本地端到端联调
	var src model.IpSource
	if err := db.Where("name = ?", "本机直连演示").First(&src).Error; err != nil {
		src = model.IpSource{
			Name: "本机直连演示", Type: model.SourceStatic, Protocol: model.ProtoDirect,
			Country: "cn", City: "local", PoolSize: 10, HealthCheck: false,
		}
		if err := db.Create(&src).Error; err != nil {
			return fmt.Errorf("seed source: %w", err)
		}
		log.Println("[seed] 创建演示 IP 源: 本机直连演示(direct)")
	}

	// 演示产品：端口 9090
	var prod model.Product
	if err := db.Where("name = ?", "演示产品").First(&prod).Error; err != nil {
		prod = model.Product{
			Name: "演示产品", Description: "direct 协议演示，无上游代理直接转发",
			ListenPort: 9090, BillingType: model.BillingTraffic,
			PricePerGB: 1.0, FailoverCount: 3, ConnectTimeoutSec: 5,
		}
		if err := db.Create(&prod).Error; err != nil {
			return fmt.Errorf("seed product: %w", err)
		}
		db.Create(&model.ProductSource{ProductID: prod.ID, SourceID: src.ID, Weight: 1})
		log.Println("[seed] 创建演示产品: 端口 9090")
	}

	// 演示订单：代理账密 demouser / demopass
	var order model.UserOrder
	if err := db.Where("proxy_username = ?", "demouser").First(&order).Error; err != nil {
		order = model.UserOrder{
			UserID: demo.ID, ProductID: prod.ID,
			ProxyUsername: "demouser", ProxyPassword: "demopass",
		}
		if err := db.Create(&order).Error; err != nil {
			return fmt.Errorf("seed order: %w", err)
		}
		log.Println("[seed] 创建演示订单: demouser / demopass")
	}
	return nil
}
