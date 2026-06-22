"""
文件名: tui.py
功能:   终端交互界面（Text User Interface）。为不熟悉命令行参数的使用者提供菜单式
        操作：内置 5 种预设扫描模式，并通过一系列 ask_* 辅助函数引导用户逐项输入/
        确认参数，最终调用 run_scan 执行。是 main.py 的「友好交互」替代入口。
作者:   李豪
版本:   v3.0
创建时间: 2026-06
"""

import os
import sys
from dataclasses import replace
from pathlib import Path

import urllib3

# 把项目根目录加入模块搜索路径，保证 import core.* 可用
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.runner import ScanOptions, run_scan

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BANNER = r"""
    __      __ZW_ Recon Tool v3.0 [TUI]
    \ \    / /_ |__  | | |
     \ \  / /| |  / /| | |
      \ \/ / | | / / | | |
       \  /  | |/ /_ |_|_|
        \/   |_|____|(_|_)
"""


# 预设模式表: 编号 -> (模式名称, 对应的 ScanOptions 参数组合)
# 每个预设是一套调好的参数，覆盖从「轻量存活探测」到「JS 收集+验证」等典型场景
PRESETS = {
    "1": (
        "低冲击存活+指纹",
        ScanOptions(
            target="moe.edu.cn",
            scenario=1,
            max_subdomains=20,
            alive_threads=5,
            enable_port_scan=False,
            enable_path_scan=False,
            enable_app_asset_scan=False,
            enable_js_discovery=False,
            include_modules="HackerTarget,FingerprintEngine",
        ),
    ),
    "2": (
        "JS 深度收集",
        ScanOptions(
            target="moe.edu.cn",
            scenario=1,
            max_subdomains=20,
            alive_threads=4,
            module_timeout=15,
            enable_port_scan=False,
            enable_path_scan=False,
            enable_app_asset_scan=False,
            enable_js_discovery=True,
            js_max_sites=8,
            js_max_scripts=4,
            js_max_bytes=500000,
            include_modules="HackerTarget,FingerprintEngine,JsDeepDiscovery",
        ),
    ),
    "3": (
        "JS 收集+低速验证",
        ScanOptions(
            target="moe.edu.cn",
            scenario=1,
            max_subdomains=20,
            alive_threads=4,
            module_timeout=15,
            enable_port_scan=False,
            enable_path_scan=False,
            enable_app_asset_scan=False,
            enable_js_discovery=True,
            enable_js_verification=True,
            js_max_sites=8,
            js_max_scripts=4,
            js_max_bytes=500000,
            js_verify_max_findings=30,
            js_verify_max_per_site=10,
            js_verify_timeout=6,
            js_verify_delay=0.3,
            include_modules="HackerTarget,FingerprintEngine,JsDeepDiscovery,JsFindingVerifier",
        ),
    ),
    "4": (
        "小范围路径发现",
        ScanOptions(
            target="moe.edu.cn",
            scenario=1,
            max_subdomains=5,
            alive_threads=3,
            module_timeout=15,
            enable_port_scan=False,
            enable_path_scan=True,
            enable_app_asset_scan=False,
            enable_js_discovery=False,
            path_threads=2,
            max_paths=40,
            include_modules="HackerTarget,FingerprintEngine,PathBrute",
        ),
    ),
    "5": (
        "自定义参数",
        ScanOptions(
            target="moe.edu.cn",
            scenario=1,
            max_subdomains=20,
            alive_threads=4,
            module_timeout=15,
            enable_port_scan=False,
            enable_path_scan=False,
            enable_app_asset_scan=False,
            enable_js_discovery=True,
            enable_js_verification=False,
            js_max_sites=8,
            js_max_scripts=4,
            js_max_bytes=500000,
        ),
    ),
}


def main():
    """TUI 主循环：展示菜单 -> 选择预设 -> 补充/自定义参数 -> 确认 -> 运行 -> 是否继续。"""
    while True:
        clear_screen()
        print(BANNER)
        print("请选择运行模式：")
        for key, (name, _) in PRESETS.items():
            print(f"  {key}. {name}")
        print("  q. 退出")

        choice = read_input("\n输入编号 [默认 3]: ").strip().lower() or "3"
        if choice in {"q", "quit", "exit"}:
            print("已退出。")
            return
        if choice not in PRESETS:
            pause("输入无效。")
            continue

        preset_name, preset = PRESETS[choice]
        options = replace(preset)  # 复制一份预设，避免修改全局 PRESETS
        print(f"\n当前模式: {preset_name}")
        options = ask_common_options(options)  # 询问通用参数（目标、线程数等）
        if choice == "5":
            options = ask_custom_options(options)  # 模式 5 额外询问全部细化参数

        print_summary(options)
        if not ask_bool("确认开始运行", default=True):
            pause("已取消本次运行。")
            continue

        run_scan(options)
        if not ask_bool("\n是否返回菜单继续", default=False):
            return


def ask_common_options(options):
    """询问所有模式都需要的通用参数，返回更新后的 options。"""
    target = ask_text("目标域名", options.target)
    output_dir = ask_text("报告输出目录", options.output_dir)
    max_subdomains = ask_int("最多探测子域名数，0 表示不限制", options.max_subdomains, minimum=0)
    alive_threads = ask_int("存活检测线程数", options.alive_threads, minimum=1)

    return replace(
        options,
        target=target,
        output_dir=output_dir,
        max_subdomains=max_subdomains,
        alive_threads=alive_threads,
    )


def ask_custom_options(options):
    """「自定义参数」模式下，逐项询问场景、各扫描开关及其细化参数，返回更新后的 options。"""
    scenario = ask_choice("运行场景 1=仅被动 2=主动限并发 3=不限制", {"1", "2", "3"}, str(options.scenario))
    options = replace(
        options,
        scenario=int(scenario),
        module_timeout=ask_int("单模块超时秒数", options.module_timeout, minimum=1),
        enable_port_scan=ask_bool("启用端口扫描", options.enable_port_scan),
        enable_path_scan=ask_bool("启用路径发现", options.enable_path_scan),
        enable_app_asset_scan=ask_bool("启用 App 资产线索", options.enable_app_asset_scan),
        enable_js_discovery=ask_bool("启用 JS 深度收集", options.enable_js_discovery),
    )

    if options.enable_path_scan:
        options = replace(
            options,
            path_threads=ask_optional_int("路径发现线程数", options.path_threads, minimum=1),
            max_paths=ask_optional_int("每站最多路径数", options.max_paths, minimum=1),
            path_dict=ask_optional_text("路径字典文件", options.path_dict),
        )

    if options.enable_js_discovery:
        options = replace(
            options,
            js_max_sites=ask_optional_int("JS 最多分析站点数", options.js_max_sites, minimum=1),
            js_max_scripts=ask_optional_int("每站最多 JS 文件数", options.js_max_scripts, minimum=1),
            js_max_bytes=ask_optional_int("单 JS 最大读取字节", options.js_max_bytes, minimum=20000),
            enable_js_verification=ask_bool("启用 JS 发现验证", options.enable_js_verification),
        )
        if options.enable_js_verification:
            options = replace(
                options,
                js_verify_max_findings=ask_optional_int(
                    "JS 验证总上限", options.js_verify_max_findings, minimum=1
                ),
                js_verify_max_per_site=ask_optional_int(
                    "JS 验证每站上限", options.js_verify_max_per_site, minimum=1
                ),
                js_verify_timeout=ask_optional_int(
                    "JS 验证单请求超时", options.js_verify_timeout, minimum=1
                ),
                js_verify_delay=ask_float("JS 验证请求间隔秒", options.js_verify_delay or 0.2, minimum=0.0),
            )

    include_modules = ask_optional_text("只启用模块，逗号分隔", options.include_modules)
    exclude_modules = ask_optional_text("排除模块，逗号分隔", options.exclude_modules)
    return replace(options, include_modules=include_modules, exclude_modules=exclude_modules)


def print_summary(options):
    """运行前打印参数清单，供用户最终核对。"""
    print("\n运行确认：")
    print(f"  target: {options.target}")
    print(f"  scenario: {options.scenario}")
    print(f"  max_subdomains: {options.max_subdomains}")
    print(f"  alive_threads: {options.alive_threads}")
    print(f"  output_dir: {options.output_dir}")
    print(f"  port_scan: {'启用' if options.enable_port_scan else '跳过'}")
    print(f"  path_scan: {'启用' if options.enable_path_scan else '跳过'}")
    print(f"  app_asset: {'启用' if options.enable_app_asset_scan else '跳过'}")
    print(f"  js_discovery: {'启用' if options.enable_js_discovery else '跳过'}")
    print(f"  js_verify: {'启用' if options.enable_js_verification else '跳过'}")
    print(f"  include_modules: {options.include_modules or '全部'}")
    print(f"  exclude_modules: {options.exclude_modules or '无'}")


# ----------------------------------------------------------------------
# 以下为一组输入辅助函数：统一处理「显示默认值、回车取默认、非法输入重试」的交互
# ----------------------------------------------------------------------

def ask_text(label, default):
    """询问文本，回车则返回默认值。"""
    value = read_input(f"{label} [{default}]: ").strip()
    return value or default


def ask_optional_text(label, default):
    """询问可选文本（默认可为空），回车则保留原默认值。"""
    default_text = default if default is not None else "空"
    value = read_input(f"{label} [{default_text}]: ").strip()
    return value or default


def ask_int(label, default, minimum=None):
    """询问整数，校验下限，非法输入循环重试，回车取默认值。"""
    while True:
        raw = read_input(f"{label} [{default}]: ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("请输入整数。")
            continue
        if minimum is not None and value < minimum:
            print(f"不能小于 {minimum}。")
            continue
        return value


def ask_optional_int(label, default, minimum=None):
    """询问可选整数（默认可为 None），回车保留默认值。"""
    default_text = default if default is not None else "空"
    while True:
        raw = read_input(f"{label} [{default_text}]: ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("请输入整数。")
            continue
        if minimum is not None and value < minimum:
            print(f"不能小于 {minimum}。")
            continue
        return value


def ask_float(label, default, minimum=None):
    """询问浮点数，校验下限，非法输入循环重试。"""
    while True:
        raw = read_input(f"{label} [{default}]: ").strip()
        if not raw:
            return default
        try:
            value = float(raw)
        except ValueError:
            print("请输入数字。")
            continue
        if minimum is not None and value < minimum:
            print(f"不能小于 {minimum}。")
            continue
        return value


def ask_choice(label, choices, default):
    """询问枚举值，只接受 choices 集合内的输入。"""
    while True:
        value = read_input(f"{label} [{default}]: ").strip() or default
        if value in choices:
            return value
        print(f"请输入以下值之一: {', '.join(sorted(choices))}")


def ask_bool(label, default=False):
    """询问是/否，兼容 y/n、yes/no、是/否 等多种写法。"""
    suffix = "Y/n" if default else "y/N"
    while True:
        value = read_input(f"{label} [{suffix}]: ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes", "1", "true", "是"}:
            return True
        if value in {"n", "no", "0", "false", "否"}:
            return False
        print("请输入 y 或 n。")


def pause(message):
    """打印提示并等待用户回车，用于停顿展示信息。"""
    read_input(f"{message} 按回车继续...")


def clear_screen():
    """清屏（仅在真实终端下执行，重定向输出时跳过以免乱码）。"""
    if not sys.stdout.isatty():
        return
    os.system("cls" if os.name == "nt" else "clear")


def read_input(prompt):
    """统一的输入读取：捕获 Ctrl+D（EOF）时优雅退出程序。"""
    try:
        return input(prompt)
    except EOFError:
        print("\n已退出。")
        raise SystemExit(0)


if __name__ == "__main__":
    main()
