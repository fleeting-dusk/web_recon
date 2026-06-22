"""
文件名: http_client.py
功能:   统一的 HTTP 请求客户端。封装随机 User-Agent、超时、失败重试（指数退避）
        和 TLS 校验关闭等通用逻辑，供所有扫描模块复用，避免各模块重复造轮子。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

import time

import requests
from fake_useragent import UserAgent


class HttpClient:
    """统一 HTTP 客户端，对外提供 request/get 两个方法。"""

    def __init__(self):
        # 初始化随机 UA 生成器；若 fake_useragent 加载失败则置空，后续使用默认 UA 兜底
        try:
            self.ua = UserAgent()
        except Exception:
            self.ua = None

    def get_headers(self):
        """生成请求头，优先使用随机 UA，失败时回退到固定的 Chrome UA。"""
        default_ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/91.0.4472.124 Safari/537.36"
        )
        try:
            user_agent = self.ua.random if self.ua else default_ua
        except Exception:
            user_agent = default_ua

        return {
            "User-Agent": user_agent,
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Connection": "close",
        }

    def request(self, method, url, timeout=15, retries=0, retry_delay=1.0, **kwargs):
        """
        发送 HTTP 请求的通用方法。

        输入: method 请求方法；url 目标地址；timeout 超时秒数；
              retries 失败重试次数；retry_delay 重试基础间隔。
        输出: requests.Response 对象；重试用尽后仍失败则抛出最后一次异常。

        逻辑: 默认关闭 TLS 证书校验（verify=False，便于扫描自签名站点），
              失败后按指数退避（retry_delay * 2^attempt，上限 3 秒）重试。
        """
        headers = kwargs.pop("headers", self.get_headers())
        verify = kwargs.pop("verify", False)
        last_exc = None

        # 共尝试 retries+1 次：第 0 次为正常请求，之后为重试
        for attempt in range(max(0, retries) + 1):
            try:
                return requests.request(
                    method,
                    url,
                    headers=headers,
                    timeout=timeout,
                    verify=verify,
                    **kwargs,
                )
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                if attempt >= retries:  # 已是最后一次尝试，直接抛出异常
                    raise
                time.sleep(min(retry_delay * (2 ** attempt), 3.0))  # 指数退避等待

        raise last_exc

    def get(self, url, timeout=15, retries=0, retry_delay=1.0, **kwargs):
        """GET 请求快捷方法，内部直接转调 request。"""
        return self.request(
            "GET",
            url,
            timeout=timeout,
            retries=retries,
            retry_delay=retry_delay,
            **kwargs,
        )
