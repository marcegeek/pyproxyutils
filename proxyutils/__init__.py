from __future__ import annotations

import datetime as dt
import itertools
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from enum import IntEnum

import requests
import socks
from requests.adapters import HTTPAdapter
from urllib3 import Retry


class ProxyAnonymity(IntEnum):
    TRANSPARENT = 0
    ANONYMOUS = 1
    ELITE = 2


@dataclass(kw_only=True)
class Proxy:
    ip: str
    port: int | str
    protocol: str
    country: str
    uptime: float
    response_time: int | float
    last_checked: dt.timedelta
    gateway: str | None = None
    anonymity: ProxyAnonymity | None = None

    def __post_init__(self) -> None:
        if len(self.country) != 2:
            raise ValueError('Country must be a 2-letter country code')
        self.country = self.country.upper()

        # Normalize values to avoid None
        self.uptime = self.uptime or 0.0
        self.last_checked = self.last_checked or dt.timedelta.max
        self.response_time = self.response_time or float("inf")

    @property
    def url(self) -> str:
        """Return the proxy URL."""
        return f'{self.protocol.lower()}://{self.ip}:{self.port}'

    @property
    def requests_protocol(self) -> str:
        """Return the proxy protocol name as used by the `requests` library.

        For SOCKS proxies, this ensures that DNS requests are resolved on the proxy server rather than
        leaking them from the local machine.
        Converts:
            - 'socks4' -> 'socks4a'
            - 'socks5' -> 'socks5h'
        Other protocols (e.g., 'http', 'https') remain unchanged.
        """
        proto = self.protocol.lower()
        if proto == 'socks4':
            proto = 'socks4a'
        elif proto == 'socks5':
            proto = 'socks5h'
        return proto

    @property
    def requests_url(self) -> str:
        """Return the proxy URL, as used by `requests` library."""
        return f'{self.requests_protocol}://{self.ip}:{self.port}'

    @property
    def requests_proxies(self) -> dict[str, str]:
        """Return as a proxies dict, as used by the `requests` library."""
        return {'http': self.requests_url, 'https': self.requests_url}

    @staticmethod
    def sort_key(proxy: Proxy) -> tuple[float, dt.timedelta, float]:
        """Default sort key for proxy objects, from best to worst.

        Sorting criteria:
        - uptime descending (higher is better)
        - last_checked ascending (smaller timedelta = more recently checked)
        - response_time ascending (lower is better)
        """
        return -proxy.uptime, proxy.last_checked, proxy.response_time


class ResilientProxySession(requests.Session):
    """A session with a prioritized sequence of proxies.

    The proxies will be used from first to last, depending on the occurrence of proxy errors.
    The sequence will be rotated up to `max_cycles` times.
    """

    def __init__(self, proxies: Sequence[Proxy],
                 total_retries_per_proxy: bool | int | None = 8,
                 connect_retries_per_proxy: int | None = 2,
                 backoff_factor: float = 0.5,
                 max_cycles: int | None = 2,
                 timeout: float | tuple[float, float] | tuple[float, None] | None = (30, 120),
                 ):
        super().__init__()
        max_cycles = max_cycles if max_cycles is not None else 1
        if not isinstance(max_cycles, int) or max_cycles <= 0:
            raise ValueError('max_cycles must be a positive integer number')
        self._proxies: Iterator[Proxy] = itertools.chain.from_iterable(itertools.repeat(proxies, max_cycles))
        self._retry = Retry(total=total_retries_per_proxy, connect=connect_retries_per_proxy,
                            backoff_factor=backoff_factor)
        adapter = HTTPAdapter(max_retries=self._retry)
        self.mount("http://", adapter)
        self.mount("https://", adapter)
        self._timeout = timeout
        # start with the first
        self._set_next_proxy()

    def _set_next_proxy(self):
        proxy = next(self._proxies, None)
        if proxy is None:
            # FIXME error handling
            raise RuntimeError('No more proxies available')
        self.proxies = proxy.requests_proxies

    def request(self, method, url, **kwargs):
        kwargs.setdefault('timeout', self._timeout)
        try:
            return super().request(method, url, **kwargs)
        except requests.exceptions.ConnectionError as ex:
            if not self._is_proxy_error(ex):
                raise ex
            self._set_next_proxy()
            return super().request(method, url, **kwargs)

    @staticmethod
    def _is_proxy_error(ex: requests.exceptions.ConnectionError) -> bool:
        """Determine if a connection error is a proxy error.

        A proxy error can be:
        * A http(s) proxy error: a requests.exceptions.ProxyError
        * A SOCKS proxy error: a requests.exceptions.ConnectionError ultimately originated by a socks.ProxyError
        """
        if isinstance(ex, requests.exceptions.ProxyError):
            return True
        if isinstance(ex, requests.exceptions.ConnectionError):
            # search in __cause__(s) and __context__(s), looking for a socks.ProxyError
            stack, seen = [ex], set()
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                if isinstance(cur, socks.ProxyError):
                    return True
                stack.extend(filter(None, {cur.__cause__, cur.__context__}))
        return False
