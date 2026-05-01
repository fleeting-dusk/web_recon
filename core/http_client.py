import requests
from fake_useragent import UserAgent
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential


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
        return {
            "User-Agent": self.ua.random if self.ua else default_ua,
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Connection": "close",
        }

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=4, max=10),
        retry=retry_if_exception_type(requests.exceptions.RequestException),
        reraise=True,
    )
    def get(self, url, timeout=15, **kwargs):
        headers = kwargs.pop("headers", self.get_headers())
        response = requests.get(url, headers=headers, timeout=timeout, verify=False, **kwargs)
        if response.status_code == 429:
            raise requests.exceptions.RequestException("API Rate Limit (429)")
        return response
