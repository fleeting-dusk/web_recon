from dataclasses import dataclass

from core.recon_controller import ReconController


@dataclass
class ScanOptions:
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

    controller.load_modules()
    controller.run_collect_stage("passive")
    controller.run_collect_stage("active")
    controller.start_alive_check()
    controller.run_fingerprint()
    controller.run_port_scan()
    controller.run_app_asset_scan()
    controller.run_js_discovery()
    controller.run_js_verification()
    controller.run_path_scan()
    controller.report()
    return controller
