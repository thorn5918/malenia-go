# malenia-go

[malenia-open](https://github.com/yint-tech/malenia-open)（Java/Netty 代理网关平台）的 **Go 语言二次开发学习实现**。
按原项目的模块划分与语义，用 Go 重写了核心转发链路、IP 资源池与管理后台（不含 MITM/脚本扩展）。

> 许可提醒：malenia-open 仅限非商业用途免费（学习研究/个人使用），商用需联系因体公司授权。

## 与 malenia-open 的模块对应关系

| malenia-open (Java) | malenia-go (Go) | 说明 |
|---|---|---|
| `MaleniaMain` 启动序列 | `cmd/malenia/main.go` | 初始化顺序：存储→引擎→监听→API→后台作业 |
| `service/proxy/ProxyServer`（每产品一端口） | `internal/server/server.go Manager` | 监听器生命周期管理，配置变更热生效 |
| `inbound/detector/ProtocolDetector` | `serveConn` 首字节嗅探 | 0x05→SOCKS5，否则按 HTTP 处理，5s 探测超时 |
| `ProxyHttpHandler`（CONNECT/绝对URI/网关式） | `serveHTTP` | 请求行重写 + 头过滤 + 原始字节透传（keep-alive 透传） |
| `ProxySocks5Handler` | `serveSocks5` | RFC1928/1929 完整实现（greeting/账密子协商/CONNECT） |
| `handlers/RelayHandler` + `NettyUtil.replay` | `internal/relay` | 双向拷贝 + 10min 空闲判死链 + 订单级令牌桶限流 |
| `outbound/handshark/HandShakerHttps/Socks5` | `internal/upstream` | 上游 CONNECT/SOCKS5 握手，direct 支持直连拨号 |
| `outbound/IpPool` 四张索引 | `internal/pool` | 一致性哈希环 / GeoHash 网格就近 / 国家城市 / 入库顺序环 |
| `Session` + `AccessMeta` | `internal/engine.Ctx` | 会话上下文 + trace_id 追踪日志 |
| 隧道路由参数 `SessionParam#parseUserParam` | `internal/auth.ParseTunnelParams` | `用户-参数-值` 格式，`\` 转义，参数完全同名 |
| 白名单 `IpTrie` + `AuthRules` | `internal/auth.Whitelist` | CIDR 匹配 → 定位用户 → 取其订单 |
| failover `switcher/OutboundConnectTask` | `engine.AllocateAndDial` | 换 IP 重试，exclude 集合，成功出口写回哈希环粘性 |
| 计量计费 `BillService/AccessRecordCollector` | `engine.FlushLoop/HourlyBilling` + `record` | 按流量实时扣费/按次/按小时，余额耗尽自动停订单 |
| IP 下载器 `IpDownloader` + Groovy 适配 | `internal/ipres` | static(DB 表) / api(HTTP 提取, 行格式解析) |
| 池健康 `LastErrorsSlot`/池健康检查 | `pool.ProbeOnce` + `Engine` 探测循环 | 连续 3 败动态下线，带 DropReason 回调钩子 |
| controller 层 REST | `internal/api` (gin) | 登录/用户/产品/订单/源/白名单/记录/指标 |
| `Monitor/MetricService`(micrometer+MQL) | `internal/metric` | 极简计数器快照 |

## 快速开始

```bash
# 构建（需要 Go 1.23+；也可用 make build）
go build -o malenia ./cmd/malenia

# 四平台交叉编译到 dist/（windows/linux × amd64/arm64）
make release

# 运行（首次启动自动建库、建表、写入种子数据）
./malenia -db data/malenia.db -api :8080
```

Windows 用户下载 `malenia-windows-amd64.exe` 直接运行（控制台程序），浏览器打开 `http://127.0.0.1:8080/` 进入管理后台。

种子数据：

| 用途 | 账户 | 说明 |
|---|---|---|
| 后台管理 | `admin / admin123` | 管理员，余额 100000 |
| 后台用户 | `demo / demo123` | 余额 100 元 |
| 代理鉴权 | `demouser / demopass` | demo 用户的订单，绑定"演示产品"(端口 9090) |

演示 IP 源为 `direct` 协议（不带上游代理直接拨号），因此无需任何外部代理资源即可联调整条链路。

### 验证

```bash
# HTTP 代理
curl -x http://demouser:demopass@127.0.0.1:9090 http://ip-api.com/json

# HTTPS 代理（CONNECT 隧道）
curl -x http://demouser:demopass@127.0.0.1:9090 https://api.ipify.org

# SOCKS5
curl --socks5 demouser:demopass@127.0.0.1:9090 http://ip-api.com/json

# 隧道路由参数：固定会话出口
curl -x "demouser-session_id-my123:demopass@127.0.0.1:9090" http://ip-api.com/json

# 匿名请求（未命中白名单）应返回 407
curl -x http://127.0.0.1:9090 http://ip-api.com/json -i
```

单元测试：`go test ./...`

## 隧道路由参数（与 malenia 兼容）

写在代理用户名字段，`-` 分隔，值内 `-` 用 `\` 转义：

```
demouser-session_id-abc123            会话固定出口（一致性哈希环）
demouser-country-cn                   指定国家
demouser-country-cn-city-hangzhou     指定国家+城市
demouser-lng_lat-116.457_\-95.444     经纬度就近（GeoHash 网格）
demouser-outbound_prefer_ip_source-源名   偏好 IP 源
demouser-trace_id-xyz                 会话追踪日志
```

注意：负数经纬度必须转义（`\-95.444`），与 malenia 文档一致。

## 管理 API（X-Token 鉴权）

```
POST /api/login                  {username,password} -> {token}
GET  /api/me | /api/metrics | /api/health

GET/POST /api/users              管理员：用户管理
POST /api/users/:id/recharge     管理员：充值
PUT  /api/users/:id/status       管理员：启用/停用

GET/POST /api/products           产品（端口/计费/超时/容错）
POST/DELETE /api/products/:id/sources    产品绑定 IP 源（weight 加权）

GET/POST /api/orders             订单（代理账密/随机隧道/带宽/并发限制）
PUT/DELETE /api/orders/:id

GET/POST /api/sources            IP 源（static/api, direct/http/socks5 出口协议）
POST /api/sources/:id/refresh    手动同步
GET  /api/sources/:id/pool       池快照（出口/健康统计/最近错误）
GET/POST /api/sources/:id/items  static 源条目管理

GET/POST/DELETE /api/whitelist   CIDR 白名单（管理员可代配）
GET  /api/records                访问记录（用户看自己，管理员看全部）
```

响应统一为 `{code, msg, data}`。

## IP 资源入库格式（api 源）

每行一条，`#` 注释：

```
1.2.3.4:8080
5.6.7.8:1080,us,la
9.9.9.9:9999,jp,tkyo,139.7,35.6
socks5://user:pass@10.0.0.1:1080,cn,sh
```

## 已知限制与后续路线

- HTTP 代理请求按"重写请求行 + 头过滤 + 整隧道透传"处理，响应侧不解析（与 malenia 原始 relay 语义一致）；未处理 103 Early Hints 等边缘响应
- SOCKS5 仅支持 CONNECT（BIND/UDP ASSOCIATE 未实现）
- 白名单/提取解析仅支持 IPv4；单节点部署（malenia 有多节点广播）
- MITM 中间人、Groovy 脚本扩展（malenia-api）未实现——即二次开发计划中的"第四步"，暂不涉及
- 指标为内存计数器，可平滑替换为 Prometheus
