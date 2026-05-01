from core.models import ScanContext
from core.module_loader import ModuleLoader
from core.services import AliveChecker, AssetCollector, ReportService


class ReconController:
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

    def __init__(self, target, max_subdomains=500, alive_threads=30, module_timeout=25, scenario=3):
        self.context = ScanContext(target=self.clean_target(target))
        self.modules = []
        self.scenario = scenario if scenario in self.SCENARIO_PRESETS else 3
        self.scenario_config = self.SCENARIO_PRESETS[self.scenario]
        self.collector = AssetCollector(
            self.modules,
            max_subdomains=max_subdomains,
            module_timeout=module_timeout,
        )
        self.alive_checker = AliveChecker(threads=alive_threads)
        self.reporter = ReportService()

    @property
    def target(self):
        return self.context.target

    def clean_target(self, target):
        return target.replace("https://", "").replace("http://", "").strip().strip("/")

    def load_modules(self):
        self.modules = ModuleLoader().load()
        self._apply_scenario_policy()
        self.collector.modules = self.modules

    def run_collect_stage(self, category):
        if category == "active" and not self.scenario_config["enable_active_collection"]:
            print("\n[*] 当前场景禁止主动收集，已跳过 ACTIVE 阶段。")
            return
        self.collector.run_stage(category, self.target, self.context.all_subdomains)
        if self.context.all_subdomains:
            print(f"[*] {category.upper()} 阶段结束，当前唯一子域名: {len(self.context.all_subdomains)}")

    def describe_scenario(self):
        cap = self.scenario_config["active_thread_cap"]
        cap_text = "不限制" if cap is None else f"主动模块并发上限 {cap}"
        return f"{self.scenario_config['name']} | {cap_text}"

    def _apply_scenario_policy(self):
        active_cap = self.scenario_config["active_thread_cap"]
        if active_cap is None:
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

    def start_alive_check(self):
        if not self.context.all_subdomains:
            print("\n[*] 未发现可检测的子域名，跳过存活检测。")
            return

        # 直接全量存活检测，不再预筛选
        all_domains = sorted(self.context.all_subdomains)
        print(f"\n[*] 共收集到 {len(all_domains)} 个唯一子域名，开始全量存活检测...")
        self.context.alive_results = self.alive_checker.run(all_domains)
        print(f"[*] 存活检测完成，发现 {len(self.context.alive_results)} 个存活站点。")

    def run_fingerprint(self):
        if not self.context.alive_results:
            print("\n[*] 没有存活站点，跳过指纹识别。")
            return
        print("\n[*] 阶段: 深度指纹识别...")
        for module in self.modules:
            if module.category == "fingerprint":
                module.run(self.context.alive_results)

    def run_port_scan(self):
        if not self.context.alive_results:
            print("\n[*] 没有存活站点，跳过端口扫描。")
            return
        for module in self.modules:
            if module.category == "port_scan":
                self.context.port_results = module.run(self.context.alive_results)

    def run_app_asset_scan(self):
        if not self.context.alive_results:
            print("\n[*] 没有存活站点，跳过 App 资产发现。")
            return
        print("\n[*] 阶段: App 资产线索发现...")
        for module in self.modules:
            if module.category == "app_asset":
                found = module.run(self.context.alive_results)
                if found:
                    self.context.app_assets.extend(found)

    def run_path_scan(self):
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
        self.reporter.write(
            self.target,
            self.context.alive_results,
            self.context.port_results,
            self.context.app_assets,
            self.context.path_results,
        )
