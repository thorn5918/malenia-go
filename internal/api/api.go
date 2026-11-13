// Package api 管理后台 REST API（对应 malenia 的 controller 层：
// AdminController / UserInfoController / UserOperatorController / MetricController 等）
package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"malenia-go/internal/engine"
	"malenia-go/internal/ipres"
	"malenia-go/internal/metric"
	"malenia-go/internal/model"
	"malenia-go/internal/pool"
	"malenia-go/internal/server"
	"malenia-go/internal/store"
)

// Deps API 依赖
type Deps struct {
	DB      *gorm.DB
	Engine  *engine.Engine
	Servers *server.Manager
	Syncer  *ipres.Syncer
	Pools   *pool.Manager
	stop    <-chan struct{}
}

// SetStop 注入全局停止信号
func (d *Deps) SetStop(stop <-chan struct{}) { d.stop = stop }

func res(c *gin.Context, code int, msg string, data interface{}) {
	c.JSON(http.StatusOK, gin.H{"code": code, "msg": msg, "data": data})
}

func ok(c *gin.Context, data interface{})      { res(c, 0, "ok", data) }
func fail(c *gin.Context, msg string)          { res(c, 1, msg, nil) }
func failCode(c *gin.Context, msg string, code int) { res(c, code, msg, nil) }

// Register 注册路由
func Register(r *gin.Engine, d *Deps) {
	r.GET("/api/health", func(c *gin.Context) { ok(c, gin.H{"status": "up", "time": time.Now()}) })

	r.POST("/api/login", func(c *gin.Context) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.BindJSON(&body); err != nil || body.Username == "" {
			fail(c, "参数错误")
			return
		}
		var user model.UserInfo
		if err := d.DB.Where("username = ? AND password = ? AND status = ?",
			body.Username, store.HashPassword(body.Password), model.StatusEnabled).First(&user).Error; err != nil {
			fail(c, "用户名或密码错误")
			return
		}
		if user.Token == "" {
			user.Token = newToken()
			d.DB.Model(&user).UpdateColumn("token", user.Token)
		}
		ok(c, gin.H{"token": user.Token, "role": user.Role, "username": user.Username})
	})

	auth := r.Group("/api", tokenAuth(d.DB))
	{
		auth.GET("/me", func(c *gin.Context) {
			ok(c, currentUser(c))
		})
		auth.GET("/metrics", func(c *gin.Context) {
			ok(c, metric.Snapshot())
		})

		// ---------- 用户管理（管理员） ----------
		auth.GET("/users", requireAdmin(), func(c *gin.Context) {
			var rows []model.UserInfo
			if err := d.DB.Order("id").Find(&rows).Error; err != nil {
				fail(c, "查询失败")
				return
			}
			ok(c, rows)
		})
		auth.POST("/users", requireAdmin(), func(c *gin.Context) {
			var u model.UserInfo
			if err := c.BindJSON(&u); err != nil || u.Username == "" {
				fail(c, "参数错误")
				return
			}
			u.Password = store.HashPassword(firstNonEmpty(u.Password, "123456"))
			u.Token = newToken()
			u.Status = model.StatusEnabled
			if err := d.DB.Create(&u).Error; err != nil {
				fail(c, "创建失败: "+err.Error())
				return
			}
			ok(c, u)
		})
		auth.POST("/users/:id/recharge", requireAdmin(), func(c *gin.Context) {
			var body struct {
				Amount float64 `json:"amount"`
			}
			if err := c.BindJSON(&body); err != nil || body.Amount == 0 {
				fail(c, "参数错误")
				return
			}
			id := paramID(c)
			if err := d.DB.Model(&model.UserInfo{}).Where("id = ?", id).
				UpdateColumn("balance", gorm.Expr("balance + ?", body.Amount)).Error; err != nil {
				fail(c, "充值失败")
				return
			}
			ok(c, nil)
		})
		auth.PUT("/users/:id/status", requireAdmin(), func(c *gin.Context) {
			var body struct {
				Status int `json:"status"`
			}
			if err := c.BindJSON(&body); err != nil {
				fail(c, "参数错误")
				return
			}
			d.DB.Model(&model.UserInfo{}).Where("id = ?", paramID(c)).UpdateColumn("status", body.Status)
			ok(c, nil)
		})

		// ---------- 白名单 ----------
		auth.GET("/whitelist", func(c *gin.Context) {
			u := currentUser(c)
			if u.Role == model.RoleAdmin {
				list[model.AuthWhiteIp](d.DB, "1=1")(c)
				return
			}
			list[model.AuthWhiteIp](d.DB, "user_id = ?", u.ID)(c)
		})
		auth.POST("/whitelist", func(c *gin.Context) {
			var w model.AuthWhiteIp
			if err := c.BindJSON(&w); err != nil || w.CIDR == "" {
				fail(c, "参数错误")
				return
			}
			u := currentUser(c)
			// 管理员可为任意用户配置；普通用户只能给自己建
			if u.Role != model.RoleAdmin || w.UserID == 0 {
				w.UserID = u.ID
			}
			d.DB.Create(&w)
			d.Engine.Reload()
			ok(c, w)
		})
		auth.DELETE("/whitelist/:id", func(c *gin.Context) {
			d.DB.Delete(&model.AuthWhiteIp{}, paramID(c))
			d.Engine.Reload()
			ok(c, nil)
		})

		// ---------- 产品 ----------
		auth.GET("/products", func(c *gin.Context) {
			list[model.Product](d.DB, "1=1")(c)
		})
		auth.POST("/products", requireAdmin(), func(c *gin.Context) {
			var p model.Product
			if err := c.BindJSON(&p); err != nil || p.Name == "" || p.ListenPort == 0 {
				fail(c, "参数错误")
				return
			}
			p.Status = model.StatusEnabled
			if p.FailoverCount == 0 {
				p.FailoverCount = 3
			}
			if p.ConnectTimeoutSec == 0 {
				p.ConnectTimeoutSec = 5
			}
			if err := d.DB.Create(&p).Error; err != nil {
				fail(c, "创建失败: "+err.Error())
				return
			}
			_ = d.Servers.Reload()
			ok(c, p)
		})
		auth.PUT("/products/:id", requireAdmin(), func(c *gin.Context) {
			var p model.Product
			if err := c.BindJSON(&p); err != nil {
				fail(c, "参数错误")
				return
			}
			p.ID = paramID(c)
			d.DB.Save(&p)
			_ = d.Servers.Reload()
			ok(c, p)
		})
		auth.DELETE("/products/:id", requireAdmin(), func(c *gin.Context) {
			id := paramID(c)
			d.DB.Delete(&model.Product{}, id)
			d.DB.Where("product_id = ?", id).Delete(&model.ProductSource{})
			_ = d.Servers.Reload()
			d.Engine.Reload()
			ok(c, nil)
		})

		// 产品绑定 IP 源（对齐 malenia ProductSource）
		auth.POST("/products/:id/sources", requireAdmin(), func(c *gin.Context) {
			var body struct {
				SourceID uint `json:"sourceId"`
				Weight   int  `json:"weight"`
			}
			if err := c.BindJSON(&body); err != nil || body.SourceID == 0 {
				fail(c, "参数错误")
				return
			}
			var src model.IpSource
			if err := d.DB.First(&src, body.SourceID).Error; err != nil {
				fail(c, "IP 源不存在")
				return
			}
			if body.Weight <= 0 {
				body.Weight = 1
			}
			ps := model.ProductSource{ProductID: paramID(c), SourceID: body.SourceID, Weight: body.Weight}
			if err := d.DB.Create(&ps).Error; err != nil {
				fail(c, "绑定失败: "+err.Error())
				return
			}
			d.Engine.Reload()
			ok(c, ps)
		})
		auth.DELETE("/products/:id/sources/:sourceId", requireAdmin(), func(c *gin.Context) {
			id, sid := paramID(c), paramID2(c, "sourceId")
			d.DB.Where("product_id = ? AND source_id = ?", id, sid).Delete(&model.ProductSource{})
			d.Engine.Reload()
			ok(c, nil)
		})

		// ---------- 订单 ----------
		auth.GET("/orders", func(c *gin.Context) {
			u := currentUser(c)
			if u.Role == model.RoleAdmin {
				list[model.UserOrder](d.DB, "1=1")(c)
				return
			}
			list[model.UserOrder](d.DB, "user_id = ?", u.ID)(c)
		})
		auth.POST("/orders", func(c *gin.Context) {
			var o model.UserOrder
			if err := c.BindJSON(&o); err != nil || o.ProductID == 0 ||
				o.ProxyUsername == "" || o.ProxyPassword == "" {
				fail(c, "参数错误")
				return
			}
			u := currentUser(c)
			// 管理员可代建订单（body.userID 指定归属）；普通用户只能给自己建
			if u.Role != model.RoleAdmin || o.UserID == 0 {
				o.UserID = u.ID
			}
			o.Status = model.StatusEnabled
			if err := d.DB.Create(&o).Error; err != nil {
				fail(c, "创建失败(代理用户名需全局唯一): "+err.Error())
				return
			}
			d.Engine.Reload()
			ok(c, o)
		})
		auth.PUT("/orders/:id/status", func(c *gin.Context) {
			var body struct {
				Status int `json:"status"`
			}
			if err := c.BindJSON(&body); err != nil {
				fail(c, "参数错误")
				return
			}
			d.DB.Model(&model.UserOrder{}).Where("id = ?", paramID(c)).UpdateColumn("status", body.Status)
			d.Engine.Reload()
			ok(c, nil)
		})
		auth.DELETE("/orders/:id", func(c *gin.Context) {
			d.DB.Delete(&model.UserOrder{}, paramID(c))
			d.Engine.Reload()
			ok(c, nil)
		})

		// ---------- IP 源 ----------
		auth.GET("/sources", func(c *gin.Context) {
			list[model.IpSource](d.DB, "1=1")(c)
		})
		auth.POST("/sources", requireAdmin(), func(c *gin.Context) {
			var s model.IpSource
			if err := c.BindJSON(&s); err != nil || s.Name == "" || s.Type == "" {
				fail(c, "参数错误")
				return
			}
			s.Status = model.StatusEnabled
			if s.Protocol == "" {
				s.Protocol = model.ProtoHTTP
			}
			if err := d.DB.Create(&s).Error; err != nil {
				fail(c, "创建失败: "+err.Error())
				return
			}
			d.Engine.Reload()
			d.Syncer.StartSource(&s, d.stop)
			ok(c, s)
		})
		auth.POST("/sources/:id/refresh", requireAdmin(), func(c *gin.Context) {
			var s model.IpSource
			if err := d.DB.First(&s, paramID(c)).Error; err != nil {
				fail(c, "源不存在")
				return
			}
			var err error
			switch s.Type {
			case model.SourceStatic:
				err = d.Syncer.SyncStatic(&s)
			case model.SourceAPI:
				err = d.Syncer.SyncAPI(&s)
			}
			if err != nil {
				fail(c, "同步失败: "+err.Error())
				return
			}
			ok(c, nil)
		})
		auth.GET("/sources/:id/pool", func(c *gin.Context) {
			pool := d.PoolSnapshot(paramID(c))
			ok(c, pool)
		})
		auth.GET("/sources/:id/items", func(c *gin.Context) {
			list[model.IpItem](d.DB, "source_id = ?", paramID(c))(c)
		})
		auth.POST("/sources/:id/items", requireAdmin(), func(c *gin.Context) {
			var item model.IpItem
			if err := c.BindJSON(&item); err != nil || item.Host == "" || item.Port == 0 {
				fail(c, "参数错误")
				return
			}
			item.SourceID = paramID(c)
			var s model.IpSource
			if err := d.DB.First(&s, item.SourceID).Error; err != nil {
				fail(c, "源不存在")
				return
			}
			// 未显式指定协议时跟随源协议（http 源的条目默认 http 出口）
			item.Protocol = firstNonEmpty(item.Protocol, s.Protocol, model.ProtoDirect)
			d.DB.Create(&item)
			// 立即重新装载该 static 源
			if s.Type == model.SourceStatic {
				_ = d.Syncer.SyncStatic(&s)
			}
			ok(c, item)
		})
		auth.DELETE("/sources/:id/items/:itemId", requireAdmin(), func(c *gin.Context) {
			d.DB.Where("id = ? AND source_id = ?", c.Param("itemId"), c.Param("id")).Delete(&model.IpItem{})
			var s model.IpSource
			if err := d.DB.First(&s, c.Param("id")).Error; err == nil && s.Type == model.SourceStatic {
				_ = d.Syncer.SyncStatic(&s)
			}
			ok(c, nil)
		})
		auth.PUT("/sources/:id", requireAdmin(), func(c *gin.Context) {
			var s model.IpSource
			if err := c.BindJSON(&s); err != nil {
				fail(c, "参数错误")
				return
			}
			s.ID = paramID(c)
			d.DB.Save(&s)
			d.Engine.Reload()
			d.Syncer.StartSource(&s, d.stop)
			ok(c, s)
		})
		auth.DELETE("/sources/:id", requireAdmin(), func(c *gin.Context) {
			id := paramID(c)
			d.Syncer.StopSource(id)
			d.DB.Delete(&model.IpSource{}, id)
			d.DB.Where("source_id = ?", id).Delete(&model.IpItem{})
			d.DB.Where("source_id = ?", id).Delete(&model.ProductSource{})
			d.Engine.Reload()
			_ = d.Servers.Reload()
			ok(c, nil)
		})

		// ---------- 访问记录 ----------
		auth.GET("/records", func(c *gin.Context) {
			u := currentUser(c)
			q := d.DB.Model(&model.AccessRecord{}).Order("id DESC").Limit(200)
			if u.Role != model.RoleAdmin {
				q = q.Where("user_id = ?", u.ID)
			}
			var rows []model.AccessRecord
			q.Find(&rows)
			ok(c, rows)
		})
	}
}

// ---- 泛型列表工具 ----

func list[T any](db *gorm.DB, where string, args ...interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		var rows []T
		if err := db.Where(where, args...).Limit(500).Find(&rows).Error; err != nil {
			fail(c, "查询失败: "+err.Error())
			return
		}
		ok(c, rows)
	}
}

func requireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if currentUser(c).Role != model.RoleAdmin {
			failCode(c, "需要管理员权限", http.StatusForbidden)
			c.Abort()
			return
		}
	}
}

func paramID(c *gin.Context) uint {
	id, err := parseUint(c.Param("id"))
	if err != nil {
		return 0
	}
	return id
}

func paramID2(c *gin.Context, name string) uint {
	id, err := parseUint(c.Param(name))
	if err != nil {
		return 0
	}
	return id
}

func parseUint(s string) (uint, error) {
	var n uint64
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, errors.New("bad number")
		}
		n = n*10 + uint64(ch-'0')
	}
	return uint(n), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func newToken() string {
	b := make([]byte, 16)
	now := time.Now().UnixNano()
	for i := range b {
		b[i] = byte(now >> (i % 8 * 8))
	}
	return fmt.Sprintf("%x", b)
}
