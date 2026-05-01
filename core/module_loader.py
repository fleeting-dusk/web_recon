import importlib
import sys

from core.base_module import BaseModule
from core.paths import MODULES_DIR


class ModuleLoader:
    def load(self):
        modules = []
        if not MODULES_DIR.exists():
            return modules

        files = sorted(
            file.stem for file in MODULES_DIR.iterdir()
            if file.suffix == ".py" and file.name != "__init__.py"
        )
        print(f"[*] 正在扫描插件目录，发现 {len(files)} 个潜在模块...")

        for mod_name in files:
            try:
                module_path = f"modules.{mod_name}"
                if module_path in sys.modules:
                    importlib.reload(sys.modules[module_path])
                    lib = sys.modules[module_path]
                else:
                    lib = importlib.import_module(module_path)

                for attr_name in dir(lib):
                    attr = getattr(lib, attr_name)
                    if isinstance(attr, type) and issubclass(attr, BaseModule) and attr_name != "BaseModule":
                        instance = attr()
                        modules.append(instance)
                        print(f" ✅ 加载成功: [{instance.module_name}]")
            except Exception as exc:
                print(f" [!] 模块 {mod_name} 加载失败: {exc}")

        return modules
