import socket
from lib.logger import logger

_installed = False


def install_dns_resolver(dns_server: str, dns_tcp: bool = False) -> None:
    """Monkey-patch socket name resolution to use a specific DNS server.

    Useful when running through SSH tunnels / SOCKS proxies where the OS
    resolver can't reach the target DNS server, or where UDP DNS won't
    traverse the tunnel (force TCP with dns_tcp=True).

    Affects every library that resolves names via the standard socket
    APIs (impacket, requests, raw sockets, etc.).
    """
    global _installed
    if not dns_server or _installed:
        return

    try:
        import dns.resolver
        import dns.rdatatype
    except ImportError:
        logger.info("[-] dnspython not installed; -dns-server has no effect. Run: pip install dnspython")
        return

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_server]
    resolver.lifetime = 5
    resolver.timeout = 5

    _orig_getaddrinfo = socket.getaddrinfo
    _orig_gethostbyname = socket.gethostbyname

    def _is_ip(host: str) -> bool:
        try:
            socket.inet_aton(host)
            return True
        except (OSError, TypeError):
            pass
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except (OSError, AttributeError, TypeError):
            return False

    def _resolve(host: str) -> str:
        """Resolve `host` against the configured DNS server. Returns an IP on
        success. Raises socket.gaierror on failure — we deliberately do NOT
        fall back to the OS resolver, because under proxychains the libc
        resolver will be hooked and may hang indefinitely trying to resolve
        non-existent names through the proxy."""
        if not host or _is_ip(host):
            return host
        try:
            answers = resolver.resolve(host, "A", tcp=dns_tcp)
            ip = answers[0].address
            logger.debug(f"[DNS] {host} -> {ip} via {dns_server} ({'TCP' if dns_tcp else 'UDP'})")
            return ip
        except Exception as e:
            logger.debug(f"[DNS] resolution of {host} via {dns_server} failed: {e}")
            raise socket.gaierror(-2, f"Name or service not known: {host}")

    def patched_getaddrinfo(host, *args, **kwargs):
        return _orig_getaddrinfo(_resolve(host), *args, **kwargs)

    def patched_gethostbyname(host):
        return _resolve(host)

    socket.getaddrinfo = patched_getaddrinfo
    socket.gethostbyname = patched_gethostbyname
    _installed = True
    logger.info(f"[*] Custom DNS resolver active: server={dns_server} tcp={dns_tcp}")
