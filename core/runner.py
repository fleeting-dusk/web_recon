"""
文件名: runner.py
功能:   定义扫描参数集合 ScanOptions，并提供顶层入口函数 run_scan()。
        run_scan 把参数交给 ReconController，按固定顺序串起「收集 → 存活检测 →
        指纹 → 端口 → App 资产 → JS 收集/验证 → 路径爆破 → 报告」的完整流程。
        它是 main.py 与 tui.py 共同调用的统一执行入口。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

from dataclasses import dataclass

from core.recon_controller import ReconController


@dataclass
class ScanOptions:
    """
    一次扫描的全部可配置参数。用 dataclass 集中承载，便于在 CLI/TUI 间传递，
    各字段含义与 main.py 的命令行参数一一对应。
    """
    target: str
    scenario: int = 3
    max_subdomains: int = 500
    alive_threads: int = 30
    module_timeout: int = 25
    output_dir: str = "reports"
    enable_port_scan: bool = True
    enable_path_scan: bool = True
    enable_app_asset_scan: bool = True
    enable_js_discovery: bool = True
    enable_js_verification: bool = False
    path_dict: str | None = None
    path_threads: int | None = None
    max_paths: int | None = None
    js_max_sites: int | None = None
    js_max_scripts: int | None = None
    js_max_bytes: int | None = None
    js_verify_max_findings: int | None = None
    js_verify_max_per_site: int | None = None
    js_verify_timeout: int | None = None
    js_verify_delay: float | None = None
    include_modules: str | None = None
    exclude_modules: str | None = None


def run_scan(options: ScanOptions):
    """
    扫描总入口：根据 options 构建控制器并依次驱动各阶段。

    输入: options —— 一组 ScanOptions 扫描参数
    输出: 执行完毕的 ReconController（便于调用方进一步取用上下文数据）

    各阶段按固定先后顺序调用，前一阶段的产出是后一阶段的输入。
    """
    controller = ReconController(
        options.target,
        scenario=options.scenario,
        max_subdomains=options.max_subdomains,
        alive_threads=options.alive_threads,
        module_timeout=options.module_timeout,
        enable_port_scan=options.enable_port_scan,
        enable_path_scan=options.enable_path_scan,
        enable_app_asset_scan=options.enable_app_asset_scan,
        enable_js_discovery=options.enable_js_discovery,
        enable_js_verification=options.enable_js_verification,
        output_dir=options.output_dir,
        path_dict=options.path_dict,
        path_threads=options.path_threads,
        max_paths=options.max_paths,
        js_max_sites=options.js_max_sites,
        js_max_scripts=options.js_max_scripts,
        js_max_bytes=options.js_max_bytes,
        js_verify_max_findings=options.js_verify_max_findings,
        js_verify_max_per_site=options.js_verify_max_per_site,
        js_verify_timeout=options.js_verify_timeout,
        js_verify_delay=options.js_verify_delay,
        include_modules=options.include_modules,
        exclude_modules=options.exclude_modules,
    )
    print(f"[*] 当前运行场景: {controller.describe_scenario()}")
    print(
        "[*] 运行限制: "
        f"max_subdomains={options.max_subdomains}, "
        f"alive_threads={options.alive_threads}, "
        f"port_scan={'启用' if options.enable_port_scan else '跳过'}, "
        f"path_scan={'启用' if options.enable_path_scan else '跳过'}, "
        f"app_asset={'启用' if options.enable_app_asset_scan else '跳过'}, "
        f"js_discovery={'启用' if options.enable_js_discovery else '跳过'}, "
        f"js_verify={'启用' if options.enable_js_verification else '跳过'}, "
        f"max_paths={options.max_paths or '不限制'}, "
        f"js_max_sites={options.js_max_sites or '不限制'}, "
        f"include_modules={options.include_modules or '全部'}, "
        f"exclude_modules={options.exclude_modules or '无'}"
    )

    # ===== 按固定顺序串联整个信息收集流水线 =====
    controller.load_modules()              # 1. 加载全部插件模块
    controller.run_collect_stage("passive")  # 2. 被动收集子域名（第三方情报源）
    controller.run_collect_stage("active")   # 3. 主动收集子域名（DNS 爆破，受场景限制）
    controller.start_alive_check()         # 4. 子域名存活检测与拓扑分析
    controller.run_fingerprint()           # 5. Web 指纹识别
    controller.run_port_scan()             # 6. 端口扫描
    controller.run_app_asset_scan()        # 7. App 资产线索发现
    controller.run_js_discovery()          # 8. JS 深度信息收集
    controller.run_js_verification()       # 9. JS 发现低速验证
    controller.run_path_scan()             # 10. 路径爆破
    controller.report()                    # 11. 汇总生成报告
    return controller
