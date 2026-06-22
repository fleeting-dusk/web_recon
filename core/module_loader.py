"""
文件名: module_loader.py
功能:   插件动态加载器。自动扫描 modules/ 目录下的所有 .py 文件，反射出其中
        继承自 BaseModule 的类并实例化。新增模块只需在 modules/ 放一个文件，
        无需改动主程序，体现了项目的可扩展性。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

import importlib
import sys

from core.base_module import BaseModule
from core.paths import MODULES_DIR


class ModuleLoader:
    """模块加载器，对外只暴露 load() 方法。"""

    def load(self):
        """
        扫描并加载 modules/ 目录下的全部模块。

        输出: 已实例化的模块对象列表。
        逻辑: 遍历目录中的 .py 文件 -> 动态 import（已加载则 reload）->
              反射查找其中 BaseModule 的子类 -> 实例化收集。单个模块
              加载失败不影响其他模块，仅打印告警。
        """
        modules = []
        if not MODULES_DIR.exists():
            return modules

        # 收集除 __init__.py 外的所有模块文件名（不含扩展名），并排序保证加载顺序稳定
        files = sorted(
            file.stem for file in MODULES_DIR.iterdir()
            if file.suffix == ".py" and file.name != "__init__.py"
        )
        print(f"[*] 正在扫描插件目录，发现 {len(files)} 个潜在模块...")

        for mod_name in files:
            try:
                module_path = f"modules.{mod_name}"
                # 已加载过则热重载，否则首次导入
                if module_path in sys.modules:
                    importlib.reload(sys.modules[module_path])
                    lib = sys.modules[module_path]
                else:
                    lib = importlib.import_module(module_path)

                # 反射遍历模块内所有属性，筛选出 BaseModule 的子类并实例化
                for attr_name in dir(lib):
                    attr = getattr(lib, attr_name)
                    if isinstance(attr, type) and issubclass(attr, BaseModule) and attr_name != "BaseModule":
                        instance = attr()
                        modules.append(instance)
                        print(f" [+] 加载成功: [{instance.module_name}]")
            except Exception as exc:
                print(f" [!] 模块 {mod_name} 加载失败: {exc}")

        return modules
