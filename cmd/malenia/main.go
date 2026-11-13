// malenia-go: malenia-open 的 Go 版二次开发实现
//
// 启动流程（对应 malenia MaleniaMain 的初始化顺序）:
//  1. 打开数据库 + 建表 + 种子数据
//  2. 构建引擎（IP 池、资源同步器、访问记录写入器）
//  3. 按产品启动代理监听端口
//  4. 启动管理 API 与后台作业（计量刷库、按小时计费、健康探测）
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"malenia-go/internal/api"
	"malenia-go/internal/engine"
	"malenia-go/internal/ipres"
	"malenia-go/internal/model"
	"malenia-go/internal/pool"
	"malenia-go/internal/record"
	"malenia-go/internal/server"
	"malenia-go/internal/store"
	"malenia-go/internal/web"
)

// buildVersion 由构建时 ldflags -X 注入
var buildVersion = "dev"

func main() {
	var (
		version = flag.Bool("version", false, "打印版本并退出")
		dbPath      = flag.String("db", "data/malenia.db", "sqlite 数据库文件路径")
		apiAddr     = flag.String("api", ":8080", "管理 API 监听地址")
		probeTarget = flag.String("probe-target", "1.1.1.1:80", "健康探测目标 host:port")
		probeSec    = flag.Int("probe-sec", 60, "健康探测周期(秒)")
		dropHookLog = flag.Bool("drop-hook-log", true, "IP 动态下线时打印日志（未来可扩展 VPS 重拨等回调）")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if *version {
		println("malenia-go", buildVersion)
		return
	}

	// 1. 存储
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	if err := store.Migrate(db); err != nil {
		log.Fatalf("建表失败: %v", err)
	}
	if err := store.Seed(db); err != nil {
		log.Fatalf("种子数据失败: %v", err)
	}

	stop := make(chan struct{})

	// 2. 引擎
	pools := pool.NewManager(pool.Hooks{
		OnDrop: func(sourceID uint, entry *pool.Entry, reason pool.DropReason) {
			if *dropHookLog {
				log.Printf("[pool] ip 动态下线 源=%d 出口=%s 原因=%s 最近错误=%v",
					sourceID, entry.Desc(), reason, entry.LastErrors)
			}
		},
	})
	syncer := ipres.NewSyncer(db, pools)
	recorder := record.NewWriter(db)
	eng := engine.New(db, pools, syncer, recorder)

	// 健康探测：为每个启用的源启动探测循环（static/api 通用）
	go probeLoop(db, pools, *probeTarget, *probeSec, stop)

	eng.Reload()
	if err := syncer.StartAll(stop); err != nil {
		log.Fatalf("装载 ip 源失败: %v", err)
	}
	recorder.Run(stop)
	eng.FlushLoop(stop)
	eng.HourlyBilling(stop)

	// 3. 代理监听
	servers := server.NewManager(db, eng)
	if err := servers.Reload(); err != nil {
		log.Fatalf("启动代理端口失败: %v", err)
	}

	// 4. 管理 API
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	deps := &api.Deps{DB: db, Engine: eng, Servers: servers, Syncer: syncer, Pools: pools}
	deps.SetStop(stop)
	api.Register(r, deps)
	web.Register(r)
	go func() {
		log.Printf("[api] 管理后台监听 %s", *apiAddr)
		if err := r.Run(*apiAddr); err != nil {
			log.Fatalf("API 启动失败: %v", err)
		}
	}()

	log.Println("malenia-go 启动完成 (version: " + buildVersion + ")。默认账户: admin/admin123(后台) demouser/demopass(代理鉴权), 演示端口 9090")

	// 优雅退出
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("正在退出...")
	close(stop)
	time.Sleep(500 * time.Millisecond)
}

// probeLoop 周期为所有启用的源触发健康探测
func probeLoop(db *gorm.DB, pools *pool.Manager, probeTarget string, probeSec int, stop <-chan struct{}) {
	interval := time.Duration(probeSec) * time.Second
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			var sources []model.IpSource
			if err := db.Where("status = ? AND health_check = ?",
				model.StatusEnabled, true).Find(&sources).Error; err != nil {
				continue
			}
			for _, s := range sources {
				go pools.Get(s.ID).ProbeOnce(s.ID, probeTarget)
			}
		}
	}
}
