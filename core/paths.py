"""
文件名: paths.py
功能:   集中定义项目的关键目录路径常量，供全局统一引用，避免硬编码路径。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

from pathlib import Path


# 项目根目录：当前文件位于 core/ 下，向上两级即为项目根目录 web_recon/
BASE_DIR = Path(__file__).resolve().parent.parent
# 功能模块（插件）目录，存放各类子域名收集、扫描模块
MODULES_DIR = BASE_DIR / "modules"
# 数据目录，存放字典文件与指纹库 JSON
DATA_DIR = BASE_DIR / "data"
