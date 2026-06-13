# web_recon

一个面向红队信息收集场景的轻量 Web 资产侦察工具。

它的目标不是做全量平台化扫描，而是围绕一个目标域名，快速串起这几类信息：

- 子域名资产
- 存活站点
- 指纹信息
- 真实 IP / C 段拓扑
- 常见开放端口
- 敏感路径
- 与站点关联的 App 资产线索

## 功能概览

当前主流程如下：

1. 被动收集子域名
2. 主动递归爆破子域名
3. 存活检测与拓扑分析
4. 深度指纹识别
5. 端口扫描
6. App 资产线索发现
7. 路径爆破
8. 生成最终报告

项目采用模块化加载方式，`modules/` 下的模块会被自动扫描并接入流程。

## 当前模块

### 子域名收集

- `subdomain_collector.py`: `crt.sh`
- `subdomain_fofa.py`: `FOFA`
- `subdomain_wayback.py`: `Wayback Machine`
- `subdomain_alienvault.py`: `AlienVault OTX`
- `subdomain_anubis.py`: `Anubis`
- `subdomain_hackertarget.py`: `HackerTarget`
- `subdomain_rapiddns.py`: `RapidDNS`
- `subdomain_brute.py`: 递归 DNS 爆破

### 资产分析

- `fingerprint_v4.py`: Web 指纹识别
- `js_deep_discovery.py`: JS 深度信息收集，提取 API、前端路由、表单、存储键和业务线索
- `js_finding_verifier.py`: JS 发现低速验证，确认同源接口/路由是否可达或需要认证
- `port_scanner.py`: 端口扫描与协议验证
- `path_brute.py`: 路径爆破与误报过滤
- `app_asset_discovery.py`: App 资产线索发现

## 运行场景

工具支持三种运行场景：

- `1`: 仅被动收集
- `2`: 允许主动收集，但限制主动模块并发
- `3`: 不做限制

## 使用方式

### 1. 安装依赖

先准备 Python 3 环境，然后安装常用依赖：

```bash
pip install -r requirements.txt
```

### 2. 配置 API

将 [config.example.py](/D:/论文/web_recon/config.example.py:1) 复制为 `config.py`，填入你自己的配置。

当前主要使用：

- `FOFA_EMAIL`
- `FOFA_KEY`

### 3. 运行

```bash
python main.py -t example.com
```

或者指定场景：

```bash
python main.py -t example.com --scenario 2
```

也可以启动终端交互界面：

```bash
python main.py --tui
```

或者：

```bash
python tui.py
```

不带任何参数运行 `python main.py` 时，也会默认进入终端交互界面。

交互界面内置 5 个模式：

- `低冲击存活+指纹`
- `JS 深度收集`
- `JS 收集+低速验证`
- `小范围路径发现`
- `自定义参数`

### 4. 低冲击验证

对真实目标做工具验证时，建议先使用低冲击模式。该模式只使用被动收集，限制后续存活检测数量，并跳过端口扫描、路径爆破和 App 资产探测：

```bash
python main.py -t moe.edu.cn --safe-test
```

也可以手动组合参数：

```bash
python main.py -t moe.edu.cn --scenario 1 --max-subdomains 20 --alive-threads 5 --skip-port-scan --skip-path-scan --skip-app-asset
```

### 5. 小范围路径发现

默认路径字典偏低噪声，聚焦公开入口、认证页、API 文档、框架元数据和教育系统常见路径。需要小范围验证路径发现时，可以限制站点数、线程数和路径数：

```bash
python main.py -t moe.edu.cn --scenario 1 --max-subdomains 5 --alive-threads 3 --skip-port-scan --skip-app-asset --path-threads 2 --max-paths 40
```

可以通过 `--path-dict your_dict.txt` 指定 `data/` 下的字典文件，也可以传入绝对路径。

调试特定模块时，可以用 `--include-modules` 或 `--exclude-modules` 控制加载范围：

```bash
python main.py -t moe.edu.cn --scenario 1 --exclude-modules FofaScanner,WaybackSubdomain,AlienVault --max-subdomains 5 --skip-port-scan --skip-app-asset --path-threads 2 --max-paths 40
```

### 6. JS 深度信息收集

JS 深度信息收集会对存活站点的公开 HTML 和同源 JS 做静态提取，输出 API 接口、前端路由、表单入口、浏览器存储键、跨系统引用和业务线索。默认只抓同源 JS，不请求第三方脚本，也不做登录、点击、表单提交或 fuzz。

```bash
python main.py -t moe.edu.cn --scenario 1 --include-modules HackerTarget,FingerprintEngine,JsDeepDiscovery --max-subdomains 8 --alive-threads 3 --skip-port-scan --skip-app-asset --skip-path-scan --js-max-sites 4 --js-max-scripts 4
```

常用限制参数：

- `--skip-js-discovery`: 跳过 JS 深度信息收集
- `--js-max-sites`: 最多分析的存活站点数
- `--js-max-scripts`: 每站最多抓取的同源 JS 文件数
- `--js-max-bytes`: 单个 JS 文件最大读取字节数

### 7. JS 发现验证

JS 深度信息收集是静态发现，结果可能包含历史接口、前端占位路由或需要登录后才可用的业务接口。需要判断误报时，可以启用 JS 发现验证模块。

验证框架只处理同源的 `API接口`、`前端路由` 和 `表单入口`，默认采用低速请求：

- 先使用 `HEAD` 判断资源是否存在
- 对看起来只读的路径补充 `GET`
- 对疑似新增、删除、保存、上传、发短信、改密码等路径不做 `GET`，只补充 `OPTIONS`
- 不提交表单，不携带 payload，不尝试登录、不绕过权限
- 输出 `reachable`、`auth_required`、`redirect`、`possible_fallback`、`not_found`、`method_not_allowed`、`request_error` 等验证状态
- `possible_fallback` 表示接口形态路径返回了 `text/html`，可能是登录页、SPA 兜底页或统一错误页，需要结合人工授权场景再确认

示例：

```bash
python main.py -t moe.edu.cn --scenario 1 --include-modules HackerTarget,FingerprintEngine,JsDeepDiscovery,JsFindingVerifier --max-subdomains 8 --alive-threads 3 --skip-port-scan --skip-app-asset --skip-path-scan --js-max-sites 4 --js-max-scripts 4 --verify-js-findings --js-verify-max-findings 30 --js-verify-max-per-site 10 --js-verify-delay 0.3
```

## 输出结果

程序默认会在 `reports/` 目录生成最终报告：

- `target_final_report.txt`

报告主要包含：

- 按 `C 段 -> IP -> URL` 聚合的拓扑结果
- 存活站点状态码、标题、指纹
- 端口扫描结果
- App 资产线索
- JS 深度信息收集线索
- JS 发现验证结果
- 有效路径/入口

## App Assets 说明

`App Assets` 这一栏用于收集和站点直接相关的移动端资产强证据，当前默认只保留这些类型：

- `APK下载`
- `App Store`
- `应用市场`
- `Manifest关联应用`
- `PWA`
- `AssetLinks`
- `Universal Links`

不会再输出网页脚本名、前端变量名这类弱线索噪声。

## 目录结构

```text
web_recon/
├─ core/        # 控制器、服务层、模型、模块加载
├─ modules/     # 功能模块
├─ data/        # 字典与指纹规则
├─ utils/       # 辅助代码
├─ main.py      # 程序入口
└─ config.py    # 本地配置（不提交）
```

## 注意事项

- 本项目偏向轻量侦察，不追求重型漏洞利用能力。
- 部分模块依赖第三方情报源，结果会受到目标站点和接口可用性的影响。
- 主动收集和路径探测会对目标发起请求，使用前请确认边界与授权。

## 免责声明

本项目仅用于授权测试、学习研究与防御验证。请勿用于未授权目标。
