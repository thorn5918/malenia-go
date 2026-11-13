// Package web 内嵌管理后台单页（原生 HTML+JS，零构建依赖）
package web

import (
	"embed"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed admin.html
var fs embed.FS

// Register 挂载管理页面
func Register(r *gin.Engine) {
	data, _ := fs.ReadFile("admin.html")
	r.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	})
	// 兼容直接访问 /admin
	r.GET("/admin", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	})
}
