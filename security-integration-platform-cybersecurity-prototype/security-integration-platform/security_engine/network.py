"""SSRF-resistant URL preflight. Enforce again at connection time (egress firewall) in production."""
import ipaddress, socket
from urllib.parse import urlsplit

def _effective_ips(ip):
    """Return the address plus every IPv4 address embedded in it (mapped, NAT64, 6to4, Teredo)."""
    out = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped: out.append(ip.ipv4_mapped)
        if ip in ipaddress.ip_network("64:ff9b::/96") or ip in ipaddress.ip_network("64:ff9b:1::/48"):
            out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if ip.sixtofour: out.append(ip.sixtofour)
        if ip.teredo: out.extend(ip.teredo)
    return out

def _is_public(ip) -> bool:
    return all(x.is_global and not x.is_multicast for x in _effective_ips(ip))

def validate_external_url(url: str, *, allow_http: bool = False) -> str:
    try: p = urlsplit(url); port = p.port
    except Exception as exc: raise ValueError("Invalid URL.") from exc
    allowed = ("https", "http") if allow_http else ("https",)
    if p.scheme.lower() not in allowed or not p.hostname or p.username or p.password or p.fragment:
        raise ValueError("Only credential-free HTTPS URLs to public hosts are allowed.")
    host = p.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Local or internal destinations are blocked.")
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try: addresses = [ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(host, port or (443 if p.scheme == "https" else 80), type=socket.SOCK_STREAM)]
        except socket.gaierror as exc: raise ValueError("Host could not be resolved.") from exc
    if not addresses: raise ValueError("Host has no addresses.")
    if any(not _is_public(ip) for ip in addresses): raise ValueError("Private, loopback, link-local or reserved IP destinations are blocked.")
    return url
