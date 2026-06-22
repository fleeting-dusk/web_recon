"""
文件名: main.py
功能:   程序主入口（命令行版）。负责解析丰富的命令行参数、提供运行场景交互选择、
        处理 --safe-test 低冲击模式，最终组装成 ScanOptions 并调用 run_scan 启动扫描。
        不带参数或带 --tui 时则转入终端交互界面 tui.py。
作者:   李豪
版本:   v3.0
创建时间: 2026-06
"""

import argparse
import sys
from pathlib import Path

# 屏蔽 HTTPS 警告
import urllib3

# 把项目根目录加入模块搜索路径，保证 import core.* 可用
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.runner import ScanOptions, run_scan

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def choose_scenario():
    """交互式让用户选择运行场景（1/2/3），回车默认场景 3；返回场景编号。"""
    print("[*] 请选择运行场景:")
    print("    1. 场景一：不使用主动收集，只能用被动收集")
    print("    2. 场景二：都可以用，但是主动收集要限制并发数")
    print("    3. 场景三：不做任何限制")

    while True:
        choice = input("请输入场景编号 [默认 3]: ").strip()
        if not choice:
            return 3
        if choice in {"1", "2", "3"}:
            return int(choice)
        print("[!] 输入无效，请输入 1、2 或 3。")


def main():
    """主流程：无参数或带 --tui 时进入交互界面；否则解析命令行参数后执行扫描。"""
    # 不带任何参数 / 显式 --tui：直接进入终端交互界面
    if len(sys.argv) == 1 or "--tui" in sys.argv[1:]:
        from tui import main as tui_main

        tui_main()
        return

    print(r"""
    __      __ZW_ Recon Tool v3.0 [Topology Edition]
    \ \    / /_ |__  | | |
     \ \  / /| |  / /| | |
      \ \/ / | | / / | | |
       \  /  | |/ /_ |_|_|
        \/   |_|____|(_|_) 
    """)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--tui",
        action="store_true",
        help="启动终端交互界面。",
    )
    parser.add_argument("-t", "--target")
    parser.add_argument(
        "--scenario",
        type=int,
        choices=[1, 2, 3],
        help="运行场景: 1=仅被动收集, 2=主动收集限并发, 3=不做限制；不传时启动后交互选择",
    )
    parser.add_argument(
        "--max-subdomains",
        type=int,
        default=500,
        help="后续存活检测最多探测的子域名数量，0 表示不限制。",
    )
    parser.add_argument(
        "--alive-threads",
        type=int,
        default=30,
        help="存活检测线程数。",
    )
    parser.add_argument(
        "--module-timeout",
        type=int,
        default=25,
        help="单个被动模块最大运行秒数。",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="报告输出目录。",
    )
    parser.add_argument(
        "--skip-port-scan",
        action="store_true",
        help="跳过端口扫描。",
    )
    parser.add_argument(
        "--skip-path-scan",
        action="store_true",
        help="跳过路径爆破。",
    )
    parser.add_argument(
        "--skip-app-asset",
        action="store_true",
        help="跳过 App 资产线索发现。",
    )
    parser.add_argument(
        "--skip-js-discovery",
        action="store_true",
        help="跳过 JS 深度信息收集。",
    )
    parser.add_argument(
        "--verify-js-findings",
        action="store_true",
        help="启用 JS 发现低速验证，只使用 HEAD/GET/OPTIONS，不提交表单。",
    )
    parser.add_argument(
        "--path-dict",
        default=None,
        help="路径爆破字典文件名或绝对路径；默认使用 data/ai_studio_code.txt。",
    )
    parser.add_argument(
        "--path-threads",
        type=int,
        default=None,
        help="路径爆破线程数；默认由模块决定。",
    )
    parser.add_argument(
        "--max-paths",
        type=int,
        default=None,
        help="每个站点最多使用的路径字典条数。",
    )
    parser.add_argument(
        "--js-max-sites",
        type=int,
        default=None,
        help="JS 深度信息收集最多分析的站点数。",
    )
    parser.add_argument(
        "--js-max-scripts",
        type=int,
        default=None,
        help="每个站点最多抓取的同源 JS 文件数，默认 8。",
    )
    parser.add_argument(
        "--js-max-bytes",
        type=int,
        default=None,
        help="单个 JS 文件最大读取字节数，默认 800000。",
    )
    parser.add_argument(
        "--js-verify-max-findings",
        type=int,
        default=None,
        help="JS 发现验证总数量上限，默认 80。",
    )
    parser.add_argument(
        "--js-verify-max-per-site",
        type=int,
        default=None,
        help="JS 发现验证每站数量上限，默认 30。",
    )
    parser.add_argument(
        "--js-verify-timeout",
        type=int,
        default=None,
        help="JS 发现验证单请求超时秒数，默认 6。",
    )
    parser.add_argument(
        "--js-verify-delay",
        type=float,
        default=None,
        help="JS 发现验证请求间隔秒数，默认 0.2。",
    )
    parser.add_argument(
        "--include-modules",
        default=None,
        help="只启用指定模块，逗号分隔，使用类名如 HackerTarget,SubdomainCollector。",
    )
    parser.add_argument(
        "--exclude-modules",
        default=None,
        help="排除指定模块，逗号分隔，使用类名如 FofaScanner,WaybackSubdomain。",
    )
    parser.add_argument(
        "--safe-test",
        action="store_true",
        help="低冲击验证模式：默认场景一，最多 20 个子域名，5 个存活线程，并跳过端口、路径和 App 资产探测。",
    )
    args = parser.parse_args()

    if args.tui:
        from tui import main as tui_main

        tui_main()
        return

    if not args.target:
        parser.error("必须传入 -t/--target，或使用 --tui 启动终端交互界面。")

    # 低冲击验证模式：强制收紧各项限制并关闭主动扫描，适合在授权范围内做安全演示
    if args.safe_test:
        if args.scenario is None:
            args.scenario = 1
        args.max_subdomains = min(args.max_subdomains, 20) if args.max_subdomains else 20
        args.alive_threads = min(args.alive_threads, 5)
        args.skip_port_scan = True
        args.skip_path_scan = True
        args.skip_app_asset = True
        args.skip_js_discovery = True
        args.verify_js_findings = False

    # 未通过参数指定场景时，转为交互式选择
    scenario = args.scenario if args.scenario is not None else choose_scenario()

    options = ScanOptions(
        target=args.target,
        scenario=scenario,
        max_subdomains=args.max_subdomains,
        alive_threads=args.alive_threads,
        module_timeout=args.module_timeout,
        output_dir=args.output_dir,
        enable_port_scan=not args.skip_port_scan,
        enable_path_scan=not args.skip_path_scan,
        enable_app_asset_scan=not args.skip_app_asset,
        enable_js_discovery=not args.skip_js_discovery,
        enable_js_verification=args.verify_js_findings,
        path_dict=args.path_dict,
        path_threads=args.path_threads,
        max_paths=args.max_paths,
        js_max_sites=args.js_max_sites,
        js_max_scripts=args.js_max_scripts,
        js_max_bytes=args.js_max_bytes,
        js_verify_max_findings=args.js_verify_max_findings,
        js_verify_max_per_site=args.js_verify_max_per_site,
        js_verify_timeout=args.js_verify_timeout,
        js_verify_delay=args.js_verify_delay,
        include_modules=args.include_modules,
        exclude_modules=args.exclude_modules,
    )
    run_scan(options)

if __name__ == "__main__":
    main()
