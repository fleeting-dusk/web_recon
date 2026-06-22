"""
文件名: recon_controller.py
功能:   总控制器 ReconController。负责加载/筛选/配置模块，按运行场景施加策略，
        并对外提供各阶段方法（收集、存活检测、指纹、端口、App资产、JS、路径、报告）。
        是连接「参数配置」与「各功能服务/模块」的中枢调度类。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

from core.domain_utils import extract_hostname
from core.models import ScanContext
from core.module_loader import ModuleLoader
from core.services import AliveChecker, AssetCollector, ReportService, SubdomainPrioritizer


class ReconController:
    """信息收集总控制器，串联整个扫描流程的各个阶段。"""

    # 三种运行场景预设：通过开关主动收集、限制并发，控制对目标的冲击强度
    SCENARIO_PRESETS = {
        1: {
            "name": "场景一：仅被动收集",
            "enable_active_collection": False,
            "active_thread_cap": None,
        },
        2: {
            "name": "场景二：主动收集限并发",
            "enable_active_collection": True,
            "active_thread_cap": 10,
        },
        3: {
            "name": "场景三：不做限制",
            "enable_active_collection": True,
            "active_thread_cap": None,
        },
    }

    def __init__(
        self,
        target,
        max_subdomains=500,
        alive_threads=30,
        module_timeout=25,
        scenario=3,
        enable_port_scan=True,
        enable_path_scan=True,
        enable_app_asset_scan=True,
        enable_js_discovery=True,
        enable_js_verification=False,
        output_dir="reports",
        path_dict=None,
        path_threads=None,
        max_paths=None,
        js_max_sites=None,
        js_max_scripts=None,
        js_max_bytes=None,
        js_verify_max_findings=None,
        js_verify_max_per_site=None,
        js_verify_timeout=None,
        js_verify_delay=None,
        include_modules=None,
        exclude_modules=None,
    ):
        """初始化控制器：清洗目标、保存各项限制参数、装配四大服务组件。"""
        self.context = ScanContext(target=self.clean_target(target))
        self.context.all_subdomains.add(self.context.target)  # 目标本身也纳入子域名集合
        self.modules = []
        self.max_subdomains = max_subdomains if max_subdomains and max_subdomains > 0 else None
        self.enable_port_scan = enable_port_scan
        self.enable_path_scan = enable_path_scan
        self.enable_app_asset_scan = enable_app_asset_scan
        self.enable_js_discovery = enable_js_discovery
        self.enable_js_verification = enable_js_verification
        self.path_dict = path_dict
        self.path_threads = path_threads
        self.max_paths = max_paths
        self.js_max_sites = js_max_sites
        self.js_max_scripts = js_max_scripts
        self.js_max_bytes = js_max_bytes
        self.js_verify_max_findings = js_verify_max_findings
        self.js_verify_max_per_site = js_verify_max_per_site
        self.js_verify_timeout = js_verify_timeout
        self.js_verify_delay = js_verify_delay
        self.include_modules = self._normalize_module_names(include_modules)
        self.exclude_modules = self._normalize_module_names(exclude_modules)
        self.scenario = scenario if scenario in self.SCENARIO_PRESETS else 3
        self.scenario_config = self.SCENARIO_PRESETS[self.scenario]
        self.collector = AssetCollector(
            self.modules,
            max_subdomains=max_subdomains,
            module_timeout=module_timeout,
        )
        self.alive_checker = AliveChecker(threads=alive_threads)
        self.prioritizer = SubdomainPrioritizer()
        self.reporter = ReportService(output_dir=output_dir)

    @property
    def target(self):
        """目标根域名的便捷访问入口。"""
        return self.context.target

    def clean_target(self, target):
        """把用户输入的目标统一清洗为纯主机名。"""
        return extract_hostname(target)

    def load_modules(self):
        """加载全部模块，再依次：按白/黑名单筛选 -> 施加场景策略 -> 注入个性化配置。"""
        self.modules = ModuleLoader().load()
        self._filter_modules()        # include/exclude 过滤
        self._apply_scenario_policy()  # 按场景限制主动模块并发
        self._configure_modules()      # 给路径/JS 等模块下发参数
        self.collector.modules = self.modules

    def run_collect_stage(self, category):
        """运行某一类别（passive/active）的全部收集模块，并汇总去重子域名。"""
        # 场景一禁止主动收集，遇到 active 阶段直接跳过
        if category == "active" and not self.scenario_config["enable_active_collection"]:
            print("\n[*] 当前场景禁止主动收集，已跳过 ACTIVE 阶段。")
            return
        self.collector.run_stage(category, self.target, self.context.all_subdomains)
        if self.context.all_subdomains:
            print(f"[*] {category.upper()} 阶段结束，当前唯一子域名: {len(self.context.all_subdomains)}")

    def describe_scenario(self):
        """生成当前运行场景的可读描述，用于启动时打印。"""
        cap = self.scenario_config["active_thread_cap"]
        cap_text = "不限制" if cap is None else f"主动模块并发上限 {cap}"
        return f"{self.scenario_config['name']} | {cap_text}"

    def _apply_scenario_policy(self):
        """场景策略：若场景对主动模块设了并发上限，则强制收紧各主动模块的线程数。"""
        active_cap = self.scenario_config["active_thread_cap"]
        if active_cap is None:  # 不限制并发，直接返回
            return
        for module in self.modules:
            if module.category != "active":
                continue
            if hasattr(module, "thread_count"):
                original = getattr(module, "thread_count")
                limited = max(1, min(original, active_cap))
                setattr(module, "thread_count", limited)
                print(
                    f"[*] 场景策略已生效: 主动模块 {module.module_name} 并发 "
                    f"{original} -> {limited}"
                )

    def _configure_modules(self):
        """根据模块类别，把对应的命令行参数下发给路径爆破、JS 收集、JS 验证模块。"""
        for module in self.modules:
            if module.category == "path_scan" and hasattr(module, "configure"):
                module.configure(
                    dict_path=self.path_dict,
                    thread_count=self.path_threads,
                    max_paths=self.max_paths,
                )
            if module.category == "js_discovery" and hasattr(module, "configure"):
                module.configure(
                    target_domain=self.target,
                    max_sites=self.js_max_sites,
                    max_scripts=self.js_max_scripts,
                    max_bytes=self.js_max_bytes,
                )
            if module.category == "js_verify" and hasattr(module, "configure"):
                module.configure(
                    max_findings=self.js_verify_max_findings,
                    max_per_site=self.js_verify_max_per_site,
                    timeout=self.js_verify_timeout,
                    delay=self.js_verify_delay,
                )

    def _filter_modules(self):
        """按 include/exclude 名单筛选模块：先做白名单保留，再做黑名单剔除。"""
        if self.include_modules:
            self.modules = [
                module for module in self.modules
                if module.module_name.lower() in self.include_modules
            ]
        if self.exclude_modules:
            self.modules = [
                module for module in self.modules
                if module.module_name.lower() not in self.exclude_modules
            ]

    @staticmethod
    def _normalize_module_names(names):
        """把逗号分隔字符串或列表统一规整为「小写、去空格」的模块名集合，便于匹配。"""
        if not names:
            return set()
        if isinstance(names, str):
            names = names.split(",")
        return {str(name).strip().lower() for name in names if str(name).strip()}

    def start_alive_check(self):
        """对（预筛选后的）子域名做 HTTP 存活检测，结果写入 context.alive_results。"""
        if not self.context.all_subdomains:
            print("\n[*] 未发现可检测的子域名，跳过存活检测。")
            return

        probe_domains = self._select_probe_domains()
        print(
            f"\n[*] 共收集到 {len(self.context.all_subdomains)} 个唯一子域名，"
            f"本轮探测 {len(probe_domains)} 个..."
        )
        self.context.alive_results = self.alive_checker.run(probe_domains)
        print(f"[*] 存活检测完成，发现 {len(self.context.alive_results)} 个存活站点。")

    def _select_probe_domains(self):
        """
        从全部子域名中挑出本轮要探测的列表。
        当数量超过 max_subdomains 时，调用优先级排序器做预筛选并保证目标本身在内；
        否则全部纳入。
        """
        domains = set(self.context.all_subdomains)
        domains.add(self.target)

        if self.max_subdomains and len(domains) > self.max_subdomains:
            selected = self.prioritizer.select(self.target, domains, self.max_subdomains)
            if self.target not in selected:
                selected = [self.target] + selected
            selected = selected[:self.max_subdomains]
        else:
            selected = sorted(domains)

        self.context.selected_subdomains = selected
        return selected

    def run_fingerprint(self):
        """对所有存活站点运行指纹识别模块，识别结果回写到各 SiteRecord。"""
        if not self.context.alive_results:
            print("\n[*] 没有存活站点，跳过指纹识别。")
            return
        print("\n[*] 阶段: 深度指纹识别...")
        for module in self.modules:
            if module.category == "fingerprint":
                module.run(self.context.alive_results)

    def run_port_scan(self):
        """对存活站点的真实 IP 做端口扫描（受 enable_port_scan 开关控制）。"""
        if not self.enable_port_scan:
            print("\n[*] 当前配置已跳过端口扫描。")
            return
        if not self.context.alive_results:
            print("\n[*] 没有存活站点，跳过端口扫描。")
            return
        for module in self.modules:
            if module.category == "port_scan":
                self.context.port_results = module.run(self.context.alive_results)

    def run_app_asset_scan(self):
        """从存活站点页面中发现 App 资产线索（受 enable_app_asset_scan 开关控制）。"""
        if not self.enable_app_asset_scan:
            print("\n[*] 当前配置已跳过 App 资产发现。")
            return
        if not self.context.alive_results:
            print("\n[*] 没有存活站点，跳过 App 资产发现。")
            return
        print("\n[*] 阶段: App 资产线索发现...")
        for module in self.modules:
            if module.category == "app_asset":
                found = module.run(self.context.alive_results)
                if found:
                    self.context.app_assets.extend(found)

    def run_js_discovery(self):
        """对存活站点抓取并分析 JS/HTML，提取接口、路由、表单等线索。"""
        if not self.enable_js_discovery:
            print("\n[*] 当前配置已跳过 JS 深度信息收集。")
            return
        if not self.context.alive_results:
            print("\n[*] 没有存活站点，跳过 JS 深度信息收集。")
            return
        print("\n[*] 阶段: JS 深度信息收集...")
        for module in self.modules:
            if module.category == "js_discovery":
                found = module.run(self.context.alive_results)
                if found:
                    self.context.js_findings.extend(found)

    def run_js_verification(self):
        """对 JS 发现的线索做低速、只读的可达性验证（受 enable_js_verification 开关控制）。"""
        if not self.enable_js_verification:
            print("\n[*] 当前配置未启用 JS 发现验证。")
            return
        if not self.context.js_findings:
            print("\n[*] 没有 JS 发现线索，跳过 JS 发现验证。")
            return
        print("\n[*] 阶段: JS 发现低速验证...")
        for module in self.modules:
            if module.category == "js_verify":
                found = module.run(self.context.js_findings)
                if found:
                    self.context.js_verifications.extend(found)

    def run_path_scan(self):
        """对真实物理站点做路径爆破（受 enable_path_scan 开关控制）。"""
        if not self.enable_path_scan:
            print("\n[*] 当前配置已跳过路径爆破。")
            return
        # 只对非 CDN、状态码为 200/403 的真实站点爆破，避免对 CDN 节点产生无效请求
        live_urls = [
            site.url for site in self.context.alive_results
            if site.status in (200, 403) and not site.is_cdn
        ]
        if live_urls:
            print(f"\n[*] 阶段: 路径爆破，正在探测 {len(live_urls)} 个真实物理站点...")
        else:
            print("\n[*] 没有符合条件的真实站点，跳过路径爆破。")
            return
        for module in self.modules:
            if module.category == "path_scan":
                found = module.run(live_urls)
                if found:
                    self.context.path_results.extend(found)

    def report(self):
        """汇总上下文中的全部结果，交给报告服务生成最终报告文件。"""
        self.reporter.write(
            self.target,
            self.context.alive_results,
            self.context.port_results,
            self.context.app_assets,
            self.context.js_findings,
            self.context.js_verifications,
            self.context.path_results,
        )
