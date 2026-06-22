"""
文件名: domain_utils.py
功能:   域名处理工具函数。提供「从任意字符串中提取纯主机名」和「判断主机名是否
        归属于目标根域名」两个基础能力，是各收集模块过滤结果的公共依赖。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

from urllib.parse import urlparse


def extract_hostname(value):
    """
    从任意输入中提取纯净的主机名（小写、去掉协议/端口/路径）。

    输入: value —— 可能是 URL、带端口的域名、或纯域名字符串
    输出: 纯主机名字符串，无法解析时返回空字符串

    逻辑: 若输入不含 "://"，先补 "//" 让 urlparse 能正确识别主机部分；
          再兜底用字符串切割去掉路径和端口。
    """
    raw = str(value or "").strip()
    if not raw:
        return ""

    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]
    return host.strip().strip(".").lower()


def belongs_to_domain(hostname, root_domain):
    """
    判断 hostname 是否属于 root_domain（即等于根域名，或是其子域名）。

    输入: hostname —— 待判断的主机名；root_domain —— 目标根域名
    输出: 布尔值。例如 api.example.com 属于 example.com，返回 True。

    用于过滤第三方情报源返回的无关域名，保证只保留目标范围内的资产。
    """
    host = extract_hostname(hostname)
    root = extract_hostname(root_domain)
    return bool(host and root and (host == root or host.endswith(f".{root}")))
