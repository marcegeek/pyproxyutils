import requests

from proxyutils import proxydb, ResilientProxySession


def print_origin_ip(session: requests.Session | None = None):
    get = session.get if session else requests.get
    try:
        res = get('https://httpbin.org/ip')
        if res.ok:
            print(f"httpbin.org says IP is: {res.json()['origin']}")
        else:
            print(f'Error: httpbin.org responded with: {res.status_code} {res.reason}')
    except requests.exceptions.RequestException as ex:
        print(f'Request failed: {ex}')


print('Getting IP with httpbin.org:')
print('Without a proxy:')
print_origin_ip()
print()
proxies = proxydb.get_proxies(countries=['US', 'DE'], protocols=['http'])
with ResilientProxySession(proxies) as ses:
    print('With a proxy:')
    print_origin_ip(session=ses)
