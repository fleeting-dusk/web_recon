import time

import requests
from fake_useragent import UserAgent


class HttpClient:
    def __init__(self):
        try:
            self.ua = UserAgent()
        except Exception:
            self.ua = None

    def get_headers(self):
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
        headers = kwargs.pop("headers", self.get_headers())
        verify = kwargs.pop("verify", False)
        last_exc = None

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
                if attempt >= retries:
                    raise
                time.sleep(min(retry_delay * (2 ** attempt), 3.0))

        raise last_exc

    def get(self, url, timeout=15, retries=0, retry_delay=1.0, **kwargs):
        return self.request(
            "GET",
            url,
            timeout=timeout,
            retries=retries,
            retry_delay=retry_delay,
            **kwargs,
        )
