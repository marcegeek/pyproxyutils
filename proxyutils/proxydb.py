"""ProxyDB (https://proxydb.net) scraping module."""

import datetime as dt
import logging
import re
import urllib.parse
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable, Any

import pytimeparse2
import requests
from bs4 import BeautifulSoup, Tag

from proxyutils import Proxy, ProxyAnonymity

BASE_URL = 'https://proxydb.net'
INVISIBLE_REGEX = re.compile(r'display\s*:\s*none')
ALPHA_REGEX = re.compile(r'[a-z]+', re.IGNORECASE)
CLEAN_VALUE_REGEX = re.compile(r'[a-z0-9. ]+', re.IGNORECASE)
TOTAL_CHECKS_REGEX = re.compile(r'(?P<checks>[0-9]+) checks(?: in)? total', re.IGNORECASE)
ISOFORMAT_REGEX = re.compile(r'\d{4}(?:-\d{2}){2} \d{2}(?::\d{2}){2}')
SUCCESSFUL_DATETIME_REGEX = re.compile(f'successful check: (?P<datetime>{ISOFORMAT_REGEX.pattern})', re.IGNORECASE)
FAILED_DATETIME_REGEX = re.compile(f'failed check: (?P<datetime>{ISOFORMAT_REGEX.pattern})', re.IGNORECASE)


class ProxyDBColumns(StrEnum):
    IP = 'ip'  # proxy IP
    PORT = 'port'  # proxy port
    TYPE = 'type'  # proxy type/protocol
    COUNTRY = 'country'  # proxy 2-letter country code
    ANONYMITY = 'anonymity'  # proxy anonymity level (one of Transparent, Anonymous, High Anonymous)
    UPTIME = 'uptime'  # average uptime (percentage)
    R_TIME = 'r_time'  # average response time
    GATEWAY = 'gateway'  # proxy gateway IP (or None if same than ip)
    CHECKED = 'checked'  # last checked date (in relative time)


@dataclass(kw_only=True)
class ProxyDBProxy(Proxy):
    # Extra fields provided by this service,
    # good candidates for better sorting metrics
    uptime_checks: int
    last_successful: dt.datetime
    last_failed: dt.datetime


def get_proxies(
        countries: Iterable[str] | None = None,
        protocols: Iterable[str] | None = None,
        session: requests.Session | None = None,
) -> list[ProxyDBProxy]:
    """Download list of proxies, filtering by countries and protocols."""
    protocols = list(protocols or [])
    countries = list(countries or [])
    params: list[tuple[str, str]] = []

    for prot in protocols:
        params.append(('protocol', prot))

    for c in countries:
        if len(c) != 2:
            raise ValueError('Countries must be 2-letter country codes')

    if len(countries) == 1:
        country = countries[0].upper()
        params.append(('country', country))

    proxies: list[ProxyDBProxy] = []
    session = session or requests.Session()

    def _fetch(url: str):
        logging.info(f"Downloading {url!r}")
        res = session.get(url, timeout=15)
        res.raise_for_status()
        return BeautifulSoup(res.text, features='html.parser')

    if len(countries) <= 1:
        url = urllib.parse.urljoin(BASE_URL, f'/?{urllib.parse.urlencode(params)}')
        while url:
            soup = _fetch(url)
            proxies.extend(_parse_soup(soup))
            next_link = soup.find('a', string=lambda s: 'next page' in s.lower())
            class_ = next_link.attrs.get('class') if next_link else None
            has_next = next_link and (class_ is None or 'disabled' not in class_)
            url = urllib.parse.urljoin(BASE_URL, next_link['href']) if has_next else None
    else:
        for c in countries:
            proxies.extend(get_proxies(countries=[c], protocols=protocols, session=session))

    proxies.sort(key=ProxyDBProxy.sort_key)
    return proxies


def _remove_invisible(elems: list[Tag]):
    """Return visible elements (filter out elements hidden by inline CSS)."""
    return [e for e in elems if not (e.attrs.get('style') and INVISIBLE_REGEX.search(e['style']))]


def _parse_soup(soup: BeautifulSoup) -> list[ProxyDBProxy]:
    """Extract a list of proxies from parsed HTML."""
    table = soup.find('table')
    if not table:
        logging.warning('Proxies table not found in page')
        return []

    thead = table.find('thead')
    headers = thead.find_all('th')
    column_names: list[str] = []
    for h in headers:
        name = h.text.strip().lower()
        name = '_'.join(ALPHA_REGEX.findall(name))
        if name not in ProxyDBColumns:
            logging.warning(f'Unknown field {name!r}')
        column_names.append(name)

    for field in ProxyDBColumns:
        if field.value not in column_names:
            raise ValueError(f"Can't find known field {field.value!r} in columns {column_names!r}")

    tbody = table.find('tbody')
    if not tbody:
        return []

    not_found = tbody.find(string=lambda s: 'no proxies' in s.lower())
    if not_found:
        return []

    rows = tbody.find_all('tr')
    return [_parse_row(r, column_names) for r in rows]


def _parse_row(row_info: Tag, column_names: list[str]) -> ProxyDBProxy:
    """Parse a row from the table and return a Proxy object."""
    cells = row_info.find_all('td')
    if len(cells) != len(column_names):
        raise ValueError(f'Quantity of columns mismatch: should be {len(column_names)}, found {len(cells)}')

    proxy_kwargs: dict[str, Any] = {}
    for i, col_name in enumerate(column_names):
        if col_name not in ProxyDBColumns:
            logging.warning(f'Ignoring unknown field {col_name!r}')
            continue
        # convert column name to Proxy class field name
        if col_name == ProxyDBColumns.TYPE:
            field_name = 'protocol'
        elif col_name == ProxyDBColumns.R_TIME:
            field_name = 'response_time'
        elif col_name == ProxyDBColumns.CHECKED:
            field_name = 'last_checked'
        else:
            field_name = col_name
        extra_fields = {}
        td = cells[i]
        elems = _remove_invisible(td.find_all())
        content = ' '.join(e.text for e in elems) if elems else td.text.strip()
        content = ' '.join(CLEAN_VALUE_REGEX.findall(content)).strip()
        titles = ' '.join(e.attrs.get('title', '').strip() for e in elems) if elems else td.attrs.get('title',
                                                                                                      '').strip()
        if not content:
            content = None
        value: Any = content

        if col_name == ProxyDBColumns.IP:
            if not content:
                raise ValueError(f'Missing IP address')
        elif col_name == ProxyDBColumns.PORT:
            if not content:
                raise ValueError(f'Missing port')
        elif col_name == ProxyDBColumns.TYPE:
            if not content:
                raise ValueError(f'Missing type/protocol')
            value = content.lower()
        elif col_name == ProxyDBColumns.COUNTRY:
            if not content:
                raise ValueError(f'Missing country')
            value = content.upper()
        elif col_name == ProxyDBColumns.ANONYMITY:
            if not content:
                logging.warning(f'Missing anonymity level')
            else:
                anon = content.lower()
                if anon == 'transparent':
                    value = ProxyAnonymity.TRANSPARENT
                elif anon == 'anonymous':
                    value = ProxyAnonymity.ANONYMOUS
                elif anon in ('elite', 'high anonymous'):
                    value = ProxyAnonymity.ELITE
                else:
                    logging.warning(f'Unknown anonymity level {content!r}, assuming transparent')
                    value = ProxyAnonymity.TRANSPARENT
        elif col_name == ProxyDBColumns.UPTIME:
            try:
                value = float(content) if content else 0.0
            except ValueError:
                logging.warning(f"Couldn't parse 'uptime': {content!r}")
                value = 0.0
            checks_match = TOTAL_CHECKS_REGEX.search(titles)
            if checks_match:
                total_checks = int(checks_match['checks'])
            else:
                logging.warning(f"Couldn't find uptime total checks in {titles!r}, setting as 1")
                total_checks = 1
            extra_fields.update({'uptime_checks': total_checks})
        elif col_name == ProxyDBColumns.R_TIME:
            if content:
                value = pytimeparse2.parse(content)
                if value is None:
                    logging.warning(f"Couldn't parse 'r_time': {content!r}, setting as inf")
                    value = float('inf')
            else:
                logging.warning(f"Missing 'r_time', setting as inf")
                value = float('inf')
        elif col_name == ProxyDBColumns.CHECKED:
            if content:
                value = pytimeparse2.parse(content.replace(' ago', ''), as_timedelta=True)
                if value is None:
                    logging.warning(f"Couldn't parse 'checked': {content!r}")
                    value = dt.timedelta.max
            else:
                logging.warning(f"Missing 'checked', setting as max timedelta")
                value = dt.timedelta.max
            last_successful_match = SUCCESSFUL_DATETIME_REGEX.search(titles)
            last_failed_match = FAILED_DATETIME_REGEX.search(titles)
            if last_successful_match:
                last_successful = dt.datetime.fromisoformat(last_successful_match['datetime'])
            else:
                logging.warning(
                    f"Couldn't find last successful check in {titles!r}, setting as 1970-01-01 00:00:00 UTC")
                last_successful = dt.datetime.fromtimestamp(0)
            if last_failed_match:
                last_failed = dt.datetime.fromisoformat(last_failed_match['datetime'])
            else:
                logging.warning(f"Couldn't find last failed check in {titles!r}, setting as 1970-01-01 00:00:00 UTC")
                last_failed = dt.datetime.fromtimestamp(0)
            extra_fields.update({'last_successful': last_successful, 'last_failed': last_failed})
        proxy_kwargs[field_name] = value
        proxy_kwargs.update(extra_fields)
    return ProxyDBProxy(**proxy_kwargs)
