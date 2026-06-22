"""
文件名: models.py
功能:   使用 dataclass 定义全项目共享的数据结构（数据模型），包括站点记录、
        App 资产、JS 发现、JS 验证结果，以及贯穿整个扫描流程的上下文容器。
        各模块统一读写这些结构，保证数据在阶段间清晰传递。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

from dataclasses import dataclass, field


@dataclass
class SiteRecord:
    """单个存活站点的完整记录，是存活检测、指纹识别、报告生成的核心载体。"""
    url: str               # 站点 URL（含协议）
    ip: str                # 解析得到的 IP
    c_seg: str             # 所属 C 段（如 1.2.3.0/24），用于网络拓扑归类
    is_cdn: bool           # 是否走 CDN（影响端口/路径扫描是否跳过）
    cdn_provider: str      # CDN 厂商名；非 CDN 时为 "Real_IP"
    status: int            # HTTP 状态码
    server: str            # 响应头中的 Server 字段
    title: str             # 网页标题（已截断）
    headers: dict          # 完整响应头
    content: str           # 网页正文 HTML
    fingerprint: list[str] = field(default_factory=list)  # 命中的指纹标签
    fp_score: int = 0      # 指纹综合得分


@dataclass(frozen=True)
class AppAssetRecord:
    """App 资产线索记录（APK、应用市场、AssetLinks 等）。frozen=True 使其可哈希、便于去重。"""
    source_site: str       # 发现该线索的来源站点
    platform: str          # 平台：Android / iOS / Web
    asset_type: str        # 资产类型：APK下载 / App Store / AssetLinks 等
    identifier: str        # 唯一标识（包名、AppID、APK 文件名等）
    url: str = ""          # 关联 URL
    note: str = ""         # 备注信息
    confidence: int = 0    # 置信度（0-100）
    evidence_count: int = 1  # 证据数量（被多少来源印证）


@dataclass(frozen=True)
class JsFindingRecord:
    """从 JS/HTML 中提取的信息线索记录（API 接口、前端路由、表单入口等）。"""
    source_site: str       # 来源站点
    category: str          # 线索类别：API接口 / 前端路由 / 表单入口 / 业务线索 等
    value: str             # 线索内容（路径、路由、存储键等）
    source_url: str = ""   # 线索所在的具体文件 URL
    evidence: str = ""     # 证据描述
    confidence: int = 0    # 置信度（0-100）
    evidence_count: int = 1  # 证据数量


@dataclass(frozen=True)
class JsVerificationRecord:
    """对 JS 发现线索进行低速安全验证后的结果记录。"""
    source_site: str       # 来源站点
    category: str          # 原线索类别
    value: str             # 原线索内容
    verify_url: str        # 实际验证请求的 URL
    method: str            # 验证使用的请求方法（HEAD/GET/OPTIONS）
    status: int | None     # 响应状态码，无响应时为 None
    result: str            # 验证结论（reachable/auth_required/not_found 等）
    content_type: str = ""  # 响应内容类型
    location: str = ""     # 跳转目标（如有）
    evidence: str = ""     # 证据描述
    confidence: int = 0    # 置信度（0-100）


@dataclass
class ScanContext:
    """
    扫描上下文容器，贯穿整个扫描生命周期。
    各阶段把产出写入这里，报告阶段再统一读取，是模块间数据流转的「中枢」。
    """
    target: str                                                       # 目标根域名
    all_subdomains: set[str] = field(default_factory=set)             # 收集到的全部唯一子域名
    selected_subdomains: list[str] = field(default_factory=list)      # 预筛选后纳入探测的子域名
    alive_results: list[SiteRecord] = field(default_factory=list)     # 存活站点列表
    app_assets: list[AppAssetRecord] = field(default_factory=list)    # App 资产线索
    js_findings: list[JsFindingRecord] = field(default_factory=list)  # JS 发现线索
    js_verifications: list[JsVerificationRecord] = field(default_factory=list)  # JS 验证结果
    path_results: list[str] = field(default_factory=list)             # 路径爆破结果
    port_results: dict[str, list[str]] = field(default_factory=dict)  # 端口扫描结果（IP -> 开放端口列表）
