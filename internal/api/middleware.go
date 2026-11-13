package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"malenia-go/internal/model"
)

// tokenAuth 请求头 X-Token 鉴权中间件，并把 UserInfo 挂到 context
func tokenAuth(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("X-Token")
		if token == "" {
			failCode(c, "未登录", 401)
			c.Abort()
			return
		}
		var user model.UserInfo
		if err := db.Where("token = ? AND status = ?", token, model.StatusEnabled).
			First(&user).Error; err != nil {
			failCode(c, "登录态无效", 401)
			c.Abort()
			return
		}
		c.Set("user", &user)
		c.Next()
	}
}

func currentUser(c *gin.Context) model.UserInfo {
	if v, ok := c.Get("user"); ok {
		if u, ok := v.(*model.UserInfo); ok {
			return *u
		}
	}
	return model.UserInfo{}
}

// PoolSnapshot 指定源的池内资源快照（对齐 malenia 后台"ip 池"页面）
func (d *Deps) PoolSnapshot(sourceID uint) []gin.H {
	entries := d.Pools.Get(sourceID).Snapshot()
	out := make([]gin.H, 0, len(entries))
	for _, e := range entries {
		out = append(out, gin.H{
			"addr":       e.Desc(),
			"protocol":   e.Protocol,
			"country":    e.Country,
			"city":       e.City,
			"lng":        e.Lng,
			"lat":        e.Lat,
			"addedAt":    e.AddedAt.Format(time.RFC3339),
			"expireAt":   expireString(e.ExpireAt),
			"fails":      e.Fails,
			"success":    e.Success.Load(),
			"assigned":   e.Assigned.Load(),
			"lastErrors": e.LastErrors,
		})
	}
	return out
}

func expireString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
