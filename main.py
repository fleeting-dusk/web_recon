import argparse
import sys
from pathlib import Path

# 屏蔽 HTTPS 警告
import urllib3

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.recon_controller import ReconController

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def choose_scenario():
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
    print(r"""
    __      __ZW_ Recon Tool v3.0 [Topology Edition]
    \ \    / /_ |__  | | |
     \ \  / /| |  / /| | |
      \ \/ / | | / / | | |
       \  /  | |/ /_ |_|_|
        \/   |_|____|(_|_) 
    """)
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument(
        "--scenario",
        type=int,
        choices=[1, 2, 3],
        help="运行场景: 1=仅被动收集, 2=主动收集限并发, 3=不做限制；不传时启动后交互选择",
    )
    args = parser.parse_args()

    scenario = args.scenario if args.scenario is not None else choose_scenario()

    controller = ReconController(args.target, scenario=scenario)
    print(f"[*] 当前运行场景: {controller.describe_scenario()}")
    controller.load_modules()

    controller.run_collect_stage("passive")
    controller.run_collect_stage("active")
    controller.start_alive_check()
    controller.run_fingerprint()
    controller.run_port_scan()
    controller.run_app_asset_scan()
    controller.run_path_scan()
    controller.report()

if __name__ == "__main__":
    main()
