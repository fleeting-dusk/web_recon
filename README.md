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

将 [config.example.py](/D:/tools/information/web_recon/config.example.py:1) 复制为 `config.py`，填入你自己的配置。

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

## 输出结果

程序会在当前目录生成最终报告：

- `target_final_report.txt`

报告主要包含：

- 按 `C 段 -> IP -> URL` 聚合的拓扑结果
- 存活站点状态码、标题、指纹
- 端口扫描结果
- App 资产线索
- 敏感路径

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
