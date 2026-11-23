"""SSRF 跳转防护核心模块。

漏洞成因: 只做字面 IP 黑名单（如 ``host == "127.0.0.1"``），因此
八进制/十六进制/十进制整数等 legacy IPv4 写法、带尾部点或 IDNA 主机名、
DNS 重绑定，以及被自动跟随的 3xx 跳转都能把请求带到内网或
``169.254.169.254`` 元数据接口。

修复方向（本模块的约定）:

1. **解析后校验**: 先拆分 URL、归一化主机名（NFKC、IDNA、去尾部点、
   小写），再按 ``inet_aton`` 的 legacy 规则识别 ``0177.0.0.1``、
   ``0x7f.1``、``2130706433`` 等写法，然后才做判断。
2. **CIDR 判定**: 环回、私网、链路本地、CGNAT、组播、保留段以及云元数据
   地址全部用 :mod:`ipaddress` 网段判断，不做字符串前缀匹配。
3. **二次解析比对**: 连接前重新解析并比对地址集合，配合 :func:`ip_pin`
   把连接固定到已校验 IP，杜绝 DNS 重绑定。
4. **禁止自动跟随跳转**: 3xx 默认不跟随；只有显式给出
   ``max_redirects > 0`` 时才对跳转目标重新执行完整校验并逐跳跟随。
5. **连接层防护**: ``safe_fetch`` 只连已校验的 IP，Host/SNI 仍用原域名，
   强制超时并限制响应体大小。

公开检查函数一律不抛异常，而是返回字典 ``{"ok": bool, ...}``。``ok`` 表示
该检查本身成功且允许继续；输入非法或命中策略时 fail-closed（``ok=False``
并给出 ``error``/``reason``）。
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
import urllib.parse
from typing import Any, Callable, Iterable, Mapping, Sequence

__all__ = [
    "GuardError",
    "ALLOWED_SCHEMES",
    "DEFAULT_PORTS",
    "BLOCKED_NETWORKS",
    "METADATA_NETWORKS",
    "METADATA_HOSTNAMES",
    "BLOCKED_HOSTNAMES",
    "DEFAULT_TIMEOUT",
    "DEFAULT_MAX_BYTES",
    "parse_and_validate",
    "octal_ip_normalize",
    "dns_rebind_check",
    "cidr_block",
    "redirect_policy",
    "metadata_block",
    "second_resolve",
    "allow_scheme",
    "timeout_guard",
    "url_decode_once",
    "host_allowlist",
    "ip_pin",
    "response_limit",
    "error_map",
    "validation",
    "safe_fetch",
]


class GuardError(Exception):
    """内部使用的带错误码异常，供 :func:`error_map` 归类。"""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# 策略常量
# ---------------------------------------------------------------------------

ALLOWED_SCHEMES = frozenset({"http", "https"})

DEFAULT_PORTS = {"http": 80, "https": 443}

# 默认禁止解析到以下网段（fail-closed）。
BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",           # 本网络 / 0.0.0.0
        "10.0.0.0/8",          # 私网
        "100.64.0.0/10",       # CGNAT
        "127.0.0.0/8",         # 环回
        "169.254.0.0/16",      # 链路本地（含元数据接口）
        "172.16.0.0/12",       # 私网
        "192.0.0.0/24",        # IETF 协议分配
        "192.0.2.0/24",        # TEST-NET-1
        "192.88.99.0/24",      # 6to4 中继
        "192.168.0.0/16",      # 私网
        "198.18.0.0/15",       # 基准测试
        "198.51.100.0/24",     # TEST-NET-2
        "203.0.113.0/24",      # TEST-NET-3
        "224.0.0.0/4",         # 组播
        "240.0.0.0/4",         # 保留 / 广播
        "::/128",              # 未指定
        "::1/128",             # 环回
        "::ffff:0:0/96",       # IPv4 映射（防止绕过）
        "64:ff9b::/96",        # NAT64
        "100::/64",            # 丢弃前缀
        "2001::/32",           # Teredo
        "2001:db8::/32",       # 文档
        "2002::/16",           # 6to4
        "fc00::/7",            # 唯一本地
        "fe80::/10",           # 链路本地
        "ff00::/8",            # 组播
    )
)

# 私有网段，仅在显式 ``allow_private=True`` 时从默认阻断列表中剔除。
PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "127.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    )
)

# 云元数据端点，单独命中时给出更明确的阻断原因。
METADATA_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "169.254.169.254/32",   # AWS / GCP / Azure / OpenStack IMDS
        "169.254.170.2/32",     # AWS ECS 任务角色
        "169.254.169.123/32",   # AWS Time Sync
        "100.100.100.200/32",   # 阿里云
        "fd00:ec2::254/128",    # AWS IPv6 IMDS
        "fd00:ec2::/64",        # 同网段整体
    )
)

METADATA_HOSTNAMES = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "instance-data.ec2.internal",
        "metadata.azure.internal",
    }
)

# 这些名字即使通过注入的 resolver 返回公网地址也不应被访问。
BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "localhost6",
        "ip6-localhost",
        "ip6-loopback",
    }
) | METADATA_HOSTNAMES

DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_BYTES = 1024 * 1024

# 遇到这些 3xx 时必须保持方法/方法语义（303 一律转 GET）。
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------


def _as_int(value: Any) -> int | None:
    """宽松地把整数/整数字符串转成 int，失败返回 None。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("+-").isdigit():
        return int(value.strip())
    return None


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _result(ok: bool, **fields: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": bool(ok)}
    out.update(fields)
    out.setdefault("allowed", bool(ok))
    return out


def _blocked(reason: str, **fields: Any) -> dict[str, Any]:
    fields.setdefault("allowed", False)
    fields.setdefault("blocked", True)
    fields.setdefault("reason", reason)
    fields.setdefault("error", reason)
    out: dict[str, Any] = {"ok": False}
    out.update(fields)
    return out


def _allowed(**fields: Any) -> dict[str, Any]:
    fields.setdefault("allowed", True)
    fields.setdefault("blocked", False)
    out: dict[str, Any] = {"ok": True}
    out.update(fields)
    return out


def _to_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """把字符串/整数/地址对象转成 ip_address，失败返回 None。"""
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        pass
    # 容忍 ``1.2.3.4%eth0`` 这类作用域后缀。
    if "%" in text:
        try:
            return ipaddress.ip_address(text.split("%", 1)[0])
        except ValueError:
            return None
    return None


def _normalize_ip(ip: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """把任意输入归一化为一个可判定的 IP。

    - IPv4 映射的 IPv6 地址还原为 IPv4，避免 ``::ffff:127.0.0.1`` 绕过。
    - 6to4 / Teredo 的内嵌 IPv4 也一并展开检查见 :func:`_embedded_ipv4`。
    """
    parsed = _to_ip(ip)
    if parsed is None:
        return None
    if isinstance(parsed, ipaddress.IPv6Address):
        mapped = parsed.ipv4_mapped
        if mapped is not None:
            return mapped
    return parsed


def _embedded_ipv4(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> list[ipaddress.IPv4Address]:
    """取出 IPv6 地址中可能内嵌的 IPv4（映射、6to4、Teredo）。"""
    out: list[ipaddress.IPv4Address] = []
    if not isinstance(ip, ipaddress.IPv6Address):
        return out
    if ip.ipv4_mapped is not None:
        out.append(ip.ipv4_mapped)
    sixtofour = getattr(ip, "sixtofour", None)
    if sixtofour is not None:
        out.append(sixtofour)
    teredo = getattr(ip, "teredo", None)
    if teredo is not None:
        # Python 的 teredo 是 (server, client) 二元组。
        out.extend(teredo)
    return out


def _network_of(value: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return value
    if isinstance(value, str):
        try:
            return ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            return None
    return None


def _in_networks(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    for net in networks:
        if ip.version == net.version and ip in net:
            return net
    return None


def _parse_legacy_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """按 ``inet_aton`` 的 legacy 规则解析 IPv4 字面量。

    覆盖 ``0177.0.0.1``（八进制）、``0x7f.1``（十六进制）、``2130706433``
    （单个 32 位整数）、``127.1``（缩写）等写法；带符号、指数或空段一律
    拒绝，以免和域名混淆。
    """
    if not isinstance(host, str) or not host:
        return None
    text = host.strip()
    if not text or "%" in text:
        return None
    parts = text.split(".")
    if len(parts) > 4:
        return None
    values: list[int] = []
    for index, part in enumerate(parts):
        if not part:
            return None
        if part[:1] in "+-":
            return None
        base = 10
        digits = part
        if part[:2].lower() == "0x":
            base, digits = 16, part[2:]
        elif len(part) > 1 and part[0] == "0":
            base, digits = 8, part[1:]
        if not digits:
            return None
        try:
            value = int(digits, base)
        except ValueError:
            return None
        if value < 0:
            return None
        if index < len(parts) - 1:
            # 前三段各占一个字节。
            if value > 0xFF:
                return None
        values.append(value)
    if not values:
        return None
    if len(values) == 1:
        final = values[0]
    else:
        # 最后一段占据剩余字节数。
        remaining = 4 - (len(values) - 1)
        if values[-1] >= 0x100**remaining:
            return None
        final = values[-1]
        for offset, value in enumerate(values[:-1]):
            final |= value << (8 * (3 - offset))
    if final < 0 or final > 0xFFFFFFFF:
        return None
    return ipaddress.IPv4Address(final)


def _canonical_host(host: Any) -> str:
    """主机名归一化: NFKC、去首尾空白/方括号、去尾部点、URL 解码、IDNA、小写。

    ``%31%32%37.0.0.1`` 这类百分号编码的主机名会被解码后再判定，避免
    "解析器看作域名、连接层看作 IP" 的差异。
    """
    if host is None or not isinstance(host, str):
        return ""
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    text = text.rstrip(".")
    if not text:
        return ""
    try:
        import unicodedata

        text = unicodedata.normalize("NFKC", text)
    except Exception:  # pragma: no cover - unicodedata 总是可用
        pass
    if "%" in text:
        try:
            text = urllib.parse.unquote(text, errors="strict")
        except UnicodeDecodeError:
            return ""
        text = text.rstrip(".")
        if not text:
            return ""
    # 解码后仍含 URL 结构字符或控制字符，说明不是合法主机名。
    if any(ch in "/\\?#@[]<>\"" or ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in text):
        return ""
    # IDNA: 处理 Unicode 域名，ASCII 域名原样返回。
    if not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return ""
    return text.lower()


def _host_to_ip(host: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """把主机名按字面 IP 解析（含 legacy IPv4 写法），失败返回 None。"""
    normalized = _canonical_host(host)
    if not normalized:
        return None
    direct = _to_ip(normalized)
    if direct is not None:
        return _normalize_ip(direct)
    legacy = _parse_legacy_ipv4(normalized)
    if legacy is not None:
        return legacy
    return None


def _blocked_host_reason(host: str) -> str | None:
    """禁用主机名（localhost/云元数据别名）返回原因，否则 None。"""
    if host in METADATA_HOSTNAMES:
        return "metadata_hostname"
    if host in BLOCKED_HOSTNAMES:
        return "blocked_hostname"
    return None


def _policy_host(host: Any) -> str:
    """策略判定用的主机标识。

    在 :func:`_canonical_host` 基础上把字面 IP（含 legacy 写法）改写为规范
    形式，确保白名单、黑名单与日志看到的是同一个值。
    """
    normalized = _canonical_host(host)
    if not normalized:
        return ""
    literal = _host_to_ip(normalized)
    if literal is not None:
        return str(literal)
    return normalized


def _split_url(url: Any) -> urllib.parse.SplitResult | None:
    if not isinstance(url, str):
        return None
    raw = url.strip()
    if not raw:
        return None
    # 控制字符会被不同解析器以不同方式丢弃，直接拒绝。
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        return None
    # 浏览器把 http(s) URL 中的反斜杠当作斜杠，先统一再解析，避免
    # ``http://192.168.1.1\@example.com/`` 这类解析器差异。
    lowered = raw[:12].lower()
    if lowered.startswith("http:") or lowered.startswith("https:") or "://" not in raw:
        raw = raw.replace("\\", "/")
    try:
        return urllib.parse.urlsplit(raw)
    except ValueError:
        return None


def _call_resolver(
    resolver: Callable[..., Any],
    host: str,
    port: int | None = None,
) -> list[str]:
    """安全调用注入的解析器；解析器抛错视为解析失败。"""
    try:
        answer = resolver(host, port) if port is not None else resolver(host)
    except TypeError:
        try:
            answer = resolver(host)
        except Exception:
            return []
    except Exception:
        return []
    return _iter_addresses(answer)


def _resolve(
    host: str,
    port: int | None = None,
    resolver: Callable[..., Any] | None = None,
) -> list[str]:
    """解析主机名，返回去重后的地址字符串列表（不做策略判断）。"""
    if resolver is not None:
        return _call_resolver(resolver, host, port)
    try:
        infos = socket.getaddrinfo(host, port or 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError:
        return []
    return _iter_addresses(infos)


def _iter_addresses(answer: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    if answer is None:
        return out
    if isinstance(answer, (str, bytes)):
        candidates = [answer]
    elif isinstance(answer, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        candidates = [answer]
    else:
        try:
            candidates = list(answer)
        except TypeError:
            candidates = [answer]
    for item in candidates:
        address: str | None = None
        if isinstance(item, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            address = str(item)
        elif isinstance(item, bytes):
            address = item.decode("ascii", "ignore")
        elif isinstance(item, str):
            address = item
        elif isinstance(item, (tuple, list)) and len(item) >= 2:
            sockaddr = item[-1]
            if isinstance(sockaddr, (tuple, list)) and sockaddr:
                address = str(sockaddr[0])
            elif isinstance(sockaddr, str):
                address = sockaddr
        if not address:
            continue
        parsed = _to_ip(address.split("%", 1)[0])
        if parsed is None:
            continue
        text = str(_normalize_ip(parsed))
        if text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _addresses_for(
    host: Any,
    port: int | None = None,
    resolver: Callable[..., Any] | None = None,
) -> list[str]:
    """主机名/字面 IP → 地址列表。字面 IP 无需 DNS。"""
    literal = _host_to_ip(host)
    if literal is not None:
        return [str(literal)]
    normalized = _canonical_host(host)
    if not normalized:
        return []
    return _resolve(normalized, port, resolver)


# ---------------------------------------------------------------------------
# 1. 字面 IP 归一化（八/十六进制、缩写、整数）
# ---------------------------------------------------------------------------


def octal_ip_normalize(ip: Any, strict: bool = True) -> dict[str, Any]:
    """把任意 legacy IPv4 写法归一化成点分十进制。

    示例::

        >>> octal_ip_normalize("0177.0.0.1")["normalized"]
        '127.0.0.1'
        >>> octal_ip_normalize("0x7f.1")["normalized"]
        '127.0.0.1'
        >>> octal_ip_normalize("2130706433")["normalized"]
        '127.0.0.1'

    无法识别为 IP 字面量时返回 ``ok=False``；``strict=False`` 时把输入视为
    普通主机名并原样返回（``is_ip=False``），便于后续 DNS 解析。
    """
    if ip is None:
        return _blocked("invalid_ip", value=None, normalized=None, is_ip=False)
    if isinstance(ip, bool):
        return _blocked("invalid_ip", value=ip, normalized=None, is_ip=False)
    if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        parsed = _normalize_ip(ip)
        return _allowed(
            value=str(ip), normalized=str(parsed), is_ip=True, version=parsed.version
        )
    if isinstance(ip, int):
        candidate = _to_ip(ip)
        if candidate is None:
            return _blocked("invalid_ip", value=ip, normalized=None, is_ip=False)
        parsed = _normalize_ip(candidate)
        return _allowed(
            value=str(ip), normalized=str(parsed), is_ip=True, version=parsed.version
        )
    if not isinstance(ip, str):
        return _blocked("invalid_ip", value=ip, normalized=None, is_ip=False)

    normalized = _canonical_host(ip)
    if not normalized:
        return _blocked("invalid_ip", value=ip, normalized=None, is_ip=False)

    raw = normalized.split("%", 1)[0]
    direct = _to_ip(raw)
    if direct is not None:
        parsed = _normalize_ip(direct)
        return _allowed(
            value=ip,
            normalized=str(parsed),
            is_ip=True,
            version=parsed.version,
            legacy=normalized not in (str(direct), str(parsed)),
        )

    legacy = _parse_legacy_ipv4(raw)
    if legacy is not None:
        return _allowed(
            value=ip,
            normalized=str(legacy),
            is_ip=True,
            version=4,
            legacy=normalized not in (str(legacy),),
        )

    if strict:
        return _blocked("not_an_ip_literal", value=ip, normalized=None, is_ip=False)
    return _allowed(value=ip, normalized=normalized, is_ip=False, version=None)


# ---------------------------------------------------------------------------
# 2. CIDR 判定
# ---------------------------------------------------------------------------


def _is_blocked_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    blocked_networks: Iterable[Any] | None = None,
    allow_private: bool = False,
) -> tuple[bool, str | None, str | None]:
    """返回 (blocked, matched_network, reason)。

    ``allow_private`` 仅放开环回/RFC1918/ULA（用于受控的内部访问场景）；
    链路本地、组播、保留段以及云元数据端点始终阻断。
    """
    parsed = _normalize_ip(ip)
    if parsed is None:
        return True, None, "invalid_ip"

    for embedded in _embedded_ipv4(parsed):
        blocked, net, reason = _is_metadata_ip(embedded)
        if blocked:
            return True, net, reason
        if not allow_private:
            blocked, net, reason = _is_blocked_ip(embedded, blocked_networks, False)
            if blocked:
                return True, net, reason

    # 元数据端点优先判定，便于给出更精确的阻断原因（始终阻断）。
    blocked, net, reason = _is_metadata_ip(parsed)
    if blocked:
        return True, net, reason

    # 环回仅在显式 allow_private 时放行；其余保留类网段始终阻断。
    is_loopback = parsed.is_loopback
    if is_loopback:
        if not allow_private:
            return True, "loopback", "loopback"
    elif getattr(parsed, "is_reserved", False):
        # ::1 等地址在 ipaddress 中同时带 reserved 标记，环回需要单独放行。
        return True, "reserved", "reserved"

    if parsed.is_unspecified:
        return True, "unspecified", "unspecified"
    if parsed.is_link_local:
        return True, "link_local", "link_local"
    if parsed.is_multicast:
        return True, "multicast", "multicast"

    if not allow_private:
        blocked, net, reason = _is_private_ip(parsed)
        if blocked:
            return True, net, reason

    if blocked_networks is None:
        if allow_private:
            private = {str(n) for n in PRIVATE_NETWORKS}
            blocked_networks = [n for n in BLOCKED_NETWORKS if str(n) not in private]
        else:
            blocked_networks = BLOCKED_NETWORKS
    matched = _in_networks(
        parsed, (_network_of(n) for n in blocked_networks if _network_of(n))
    )
    if matched is not None:
        return True, str(matched), "blocked_network"

    return False, None, None


def _is_metadata_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[bool, str | None, str | None]:
    matched = _in_networks(ip, METADATA_NETWORKS)
    if matched is not None:
        return True, str(matched), "metadata_endpoint"
    return False, None, None


def _is_private_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[bool, str | None, str | None]:
    if isinstance(ip, ipaddress.IPv4Address) and ip.is_private:
        return True, "private", "private_network"
    if isinstance(ip, ipaddress.IPv6Address) and ip.is_private:
        return True, "private", "private_network"
    return False, None, None


def cidr_block(
    ip: Any,
    block_private: bool = True,
    blocked_networks: Iterable[Any] | None = None,
    allowed_networks: Iterable[Any] | None = None,
    allow_private: bool | None = None,
) -> dict[str, Any]:
    """按 CIDR 判断地址是否落在被禁止的内网/保留段。

    ``block_private`` 控制是否阻断 RFC1918/ULA 等私有网段（默认阻断）；
    显式给出 ``allow_private=True`` 时也会放开。``allowed_networks`` 为
    例外白名单，命中时放行。
    """
    if allow_private is not None:
        block_private = not allow_private
    parsed = _normalize_ip(ip)
    if parsed is None:
        return _blocked("invalid_ip", ip=str(ip), normalized=None, matched_network=None)

    if allowed_networks:
        nets = tuple(_network_of(n) for n in allowed_networks)
        matched = _in_networks(parsed, [n for n in nets if n is not None])
        if matched is not None:
            return _allowed(
                ip=str(ip),
                normalized=str(parsed),
                matched_network=str(matched),
                reason="allowlisted_network",
            )

    blocked, matched, reason = _is_blocked_ip(
        parsed,
        blocked_networks,
        allow_private=not block_private,
    )
    if blocked:
        return _blocked(
            reason or "blocked_network",
            ip=str(ip),
            normalized=str(parsed),
            matched_network=matched,
        )
    return _allowed(ip=str(ip), normalized=str(parsed), matched_network=None)


def metadata_block(
    ip_or_url: Any,
    host: Any | None = None,
    port: int | None = None,
    resolver: Callable[..., Any] | None = None,
    addresses: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """检测云元数据端点（169.254.169.254 等）及常见元数据主机名。

    可传入 IP、URL、或 (host, port) 形式。域名会先解析再逐个地址判断；
    调用方已解析过时可传 ``addresses`` 复用，避免重复 DNS。
    """
    target = ip_or_url
    hostname: str | None = None
    if isinstance(target, str) and "://" in target:
        parts = _split_url(target)
        if parts is not None:
            hostname = _canonical_host(parts.hostname)
    elif host is not None:
        hostname = _canonical_host(host)
    elif isinstance(target, str):
        hostname = _canonical_host(target)

    if hostname is not None and hostname in BLOCKED_HOSTNAMES:
        return _blocked(
            _blocked_host_reason(hostname) or "blocked_hostname",
            host=hostname,
            matched_network=None,
        )

    if addresses is not None:
        resolved = _iter_addresses(addresses)
    elif hostname is not None:
        # 字面 IP 走 legacy 解析；``_addresses_for`` 对字面量不会触发 DNS。
        literal = _host_to_ip(hostname)
        resolved = [str(literal)] if literal is not None else _addresses_for(
            hostname, port, resolver
        )
    else:
        resolved = _iter_addresses([target])

    if not resolved:
        literal = _host_to_ip(hostname) if hostname else _normalize_ip(target)
        if literal is None:
            return _blocked("unresolvable", host=hostname, matched_network=None)
        resolved = [str(literal)]

    for address in resolved:
        parsed = _normalize_ip(address)
        if parsed is None:
            continue
        for candidate in (parsed, *_embedded_ipv4(parsed)):
            blocked, matched, _reason = _is_metadata_ip(candidate)
            if blocked:
                return _blocked(
                    "metadata_endpoint",
                    host=hostname,
                    ip=address,
                    matched_network=matched,
                )
        # 链路本地 169.254.0.0/16 整体也视作元数据候选。
        if parsed.is_link_local:
            return _blocked(
                "link_local_metadata", host=hostname, ip=address, matched_network="169.254.0.0/16"
            )
    return _allowed(host=hostname, addresses=resolved, matched_network=None)


# ---------------------------------------------------------------------------
# 3. scheme / 主机白名单 / URL 解码
# ---------------------------------------------------------------------------


def allow_scheme(
    url_or_scheme: Any,
    schemes: Iterable[str] | None = None,
    allow: Iterable[str] | None = None,
) -> dict[str, Any]:
    """只允许 http/https（可由参数覆盖），其余 scheme 一律拒绝。

    拒绝 ``file:``、``gopher:``、``ftp:``、``dict:`` 等协议，避免借协议
    差异重新进入内网。解析失败或缺少 scheme 时 fail-closed。
    """
    allowed = _normalize_schemes(
        allow if allow is not None else (schemes if schemes is not None else ALLOWED_SCHEMES)
    )
    if not isinstance(url_or_scheme, str):
        return _blocked("invalid_url", scheme=None)
    raw = url_or_scheme.strip()
    if not raw:
        return _blocked("invalid_url", scheme=None)
    if "://" in raw or raw.endswith(":") or ":" in raw:
        parts = _split_url(raw)
        scheme = (parts.scheme or "").lower() if parts is not None else ""
        if not scheme and raw.endswith(":"):
            scheme = raw[:-1].lower()
    else:
        scheme = raw.lower()
    if not scheme:
        return _blocked("missing_scheme", scheme=None)
    if scheme not in allowed:
        return _blocked(
            "scheme_not_allowed", scheme=scheme, allowed_schemes=sorted(allowed)
        )
    return _allowed(scheme=scheme, allowed_schemes=sorted(allowed))


def _normalize_schemes(schemes: Any) -> set[str]:
    if isinstance(schemes, str):
        return {schemes.strip().lower()} if schemes.strip() else set()
    out: set[str] = set()
    try:
        items = list(schemes)
    except TypeError:
        return out
    for item in items:
        if isinstance(item, str) and item.strip():
            out.add(item.strip().lower())
    return out


def url_decode_once(raw: Any, max_rounds: int = 1) -> dict[str, Any]:
    """有限次 URL 解码，用于检测 ``%31%32%37`` 这类编码绕过。

    默认只解一轮（``max_rounds=1``），避免把合法参数里的 ``%25`` 过度
    解码；返回 ``changed`` 表示是否发生了改变。
    """
    if not isinstance(raw, str):
        return _blocked("invalid_url", decoded=None)
    rounds = _as_int(max_rounds)
    if rounds is None or rounds < 0:
        return _blocked("invalid_rounds", decoded=None)
    decoded = raw
    seen = {raw}
    changes = 0
    for _ in range(rounds):
        try:
            candidate = urllib.parse.unquote(decoded, errors="strict")
        except UnicodeDecodeError:
            return _blocked("invalid_encoding", decoded=None)
        if candidate in seen:
            break
        seen.add(candidate)
        decoded = candidate
        changes += 1
    return _allowed(
        value=raw,
        decoded=decoded,
        rounds_used=changes,
        changed=decoded != raw,
        percent_encoded="%" in raw,
    )


def host_allowlist(
    host: Any,
    allowlist: Iterable[str] | None = None,
    deny: Iterable[str] | None = None,
    allow_subdomains: bool = True,
) -> dict[str, Any]:
    """主机白名单校验。

    - ``allowlist=None`` 表示不启用白名单（返回 ``allowed=True``，
      ``enforced=False``），仍会执行 ``deny`` 检查。
    - 白名单项可以是精确域名，``*.example.com`` 或 ``.example.com`` 表示
      子域（``allow_subdomains`` 为真时）。
    - ``deny`` 优先于 ``allowlist``。
    """
    normalized = _policy_host(host)
    if not normalized:
        return _blocked("invalid_host", host=None)

    deny_entries = _normalize_patterns(deny)
    if _matches_patterns(normalized, deny_entries, allow_subdomains):
        return _blocked("host_denied", host=normalized)

    if allowlist is None:
        return _allowed(host=normalized, enforced=False, matched=None)

    entries = _normalize_patterns(allowlist)
    matched = _match_pattern(normalized, entries, allow_subdomains)
    if matched is None:
        # 允许 IP 字面量直接匹配白名单里的 CIDR/精确 IP。
        literal = _host_to_ip(normalized)
        if literal is not None:
            for entry in entries:
                net = _network_of(entry)
                if net is not None and literal.version == net.version and literal in net:
                    return _allowed(host=normalized, enforced=True, matched=str(net))
        return _blocked("host_not_allowlisted", host=normalized, enforced=True)
    return _allowed(host=normalized, enforced=True, matched=matched)


def _normalize_patterns(patterns: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    if not patterns:
        return out
    if isinstance(patterns, str):
        patterns = [patterns]
    try:
        items = list(patterns)
    except TypeError:
        return out
    for pattern in items:
        if not isinstance(pattern, str):
            continue
        text = pattern.strip().lower()
        if not text:
            continue
        out.append(text)
    return out


def _match_pattern(
    host: str, patterns: Sequence[str], allow_subdomains: bool
) -> str | None:
    for pattern in patterns:
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if allow_subdomains and (host == suffix or host.endswith("." + suffix)):
                return pattern
        elif pattern.startswith("."):
            suffix = pattern[1:]
            if allow_subdomains and (host == suffix or host.endswith("." + suffix)):
                return pattern
        elif host == pattern:
            return pattern
    return None


def _matches_patterns(
    host: str, patterns: Sequence[str], allow_subdomains: bool
) -> bool:
    return _match_pattern(host, patterns, allow_subdomains) is not None


# ---------------------------------------------------------------------------
# 4. 解析后校验 / 二次解析 / DNS 重绑定
# ---------------------------------------------------------------------------


def parse_and_validate(
    url: Any,
    resolver: Callable[..., Any] | None = None,
    allow_private: bool = False,
    allowed_schemes: Iterable[str] | None = None,
    allowlist: Iterable[str] | None = None,
    port: int | None = None,
    blocked_networks: Iterable[Any] | None = None,
) -> dict[str, Any]:
    """解析 URL 并完成全部静态校验，返回最终可连接的地址集合。

    流程: scheme 白名单 → host 归一化（含 legacy IP）→ 白名单 →
    元数据检查 → DNS 解析 → 每个地址按 CIDR 校验。任一地址不合格即整体
    fail-closed（DNS 轮询返回私网时不能被公网地址掩盖）。
    """
    parts = _split_url(url)
    if parts is None:
        return _blocked("invalid_url", url=url)

    scheme = (parts.scheme or "").lower()
    scheme_check = allow_scheme(scheme, allow=allowed_schemes)
    if not scheme_check["ok"]:
        return _blocked("scheme_not_allowed", url=url, scheme=scheme)

    hostname = parts.hostname
    normalized_host = _policy_host(hostname)
    if not normalized_host:
        return _blocked("missing_host", url=url)
    if normalized_host in BLOCKED_HOSTNAMES:
        return _blocked(
            _blocked_host_reason(normalized_host) or "blocked_hostname",
            url=url,
            host=normalized_host,
        )

    try:
        explicit_port = parts.port
    except ValueError:
        return _blocked("invalid_port", url=url, host=normalized_host)

    effective_port = explicit_port if explicit_port is not None else (
        port if port is not None else DEFAULT_PORTS.get(scheme, 80)
    )
    if not 1 <= int(effective_port) <= 65535:
        return _blocked("invalid_port", url=url, host=normalized_host, port=effective_port)

    allow_check = host_allowlist(normalized_host, allowlist=allowlist)
    if not allow_check["ok"]:
        return _blocked(
            allow_check.get("reason", "host_not_allowlisted"),
            url=url,
            host=normalized_host,
        )

    # 只解析一次，元数据检查与 CIDR 校验复用同一份答案，保证判定对象一致。
    addresses = _addresses_for(normalized_host, effective_port, resolver)
    if not addresses:
        return _blocked("unresolvable", url=url, host=normalized_host)

    meta_check = metadata_block(normalized_host, addresses=addresses)
    if not meta_check["ok"]:
        return _blocked(
            meta_check.get("reason", "metadata_endpoint"),
            url=url,
            host=normalized_host,
            matched_network=meta_check.get("matched_network"),
        )

    for address in addresses:
        check = cidr_block(
            address,
            block_private=not allow_private,
            blocked_networks=blocked_networks,
        )
        if not check["ok"]:
            return _blocked(
                check.get("reason", "blocked_network"),
                url=url,
                host=normalized_host,
                ip=address,
                matched_network=check.get("matched_network"),
                addresses=addresses,
            )

    literal = _host_to_ip(normalized_host)
    return _allowed(
        url=url,
        scheme=scheme,
        host=normalized_host,
        port=int(effective_port),
        path=parts.path or "/",
        query=parts.query,
        is_ip_literal=literal is not None,
        addresses=addresses,
        ip=addresses[0],
    )


def second_resolve(
    host: Any,
    expected: Any = None,
    resolver: Callable[..., Any] | None = None,
    port: int | None = None,
    allow_private: bool = False,
) -> dict[str, Any]:
    """连接前二次解析，与首次结果比对，阻断 DNS 重绑定。

    ``expected`` 可以是首次解析得到的地址列表/单个地址/IP 对象；未提供时
    只做一次新的解析并返回结果（``consistent=None``）。只要求新结果必须
    被首次结果包含，并且新结果本身通过 CIDR 校验；新出现的地址一律视为
    潜在重绑定而拒绝。
    """
    normalized_host = _canonical_host(host)
    if not normalized_host:
        return _blocked("invalid_host", host=None)

    literal = _host_to_ip(normalized_host)
    if literal is not None:
        fresh = [str(literal)]
    else:
        fresh = _resolve(normalized_host, port, resolver)
    if not fresh:
        return _blocked("unresolvable", host=normalized_host, addresses=[])

    for address in fresh:
        check = cidr_block(address, block_private=not allow_private)
        if not check["ok"]:
            return _blocked(
                check.get("reason", "blocked_network"),
                host=normalized_host,
                addresses=fresh,
                ip=address,
                matched_network=check.get("matched_network"),
                consistent=False,
            )

    if expected is None:
        return _allowed(
            host=normalized_host,
            addresses=fresh,
            first=[],
            consistent=None,
            added=[],
            removed=[],
        )

    first = _iter_addresses(expected)
    fresh_set = set(fresh)
    first_set = set(first)
    added = sorted(fresh_set - first_set)
    removed = sorted(first_set - fresh_set)
    if not fresh_set.issubset(first_set):
        return _blocked(
            "dns_rebinding_detected",
            host=normalized_host,
            addresses=fresh,
            first=first,
            consistent=False,
            added=added,
            removed=removed,
        )
    return _allowed(
        host=normalized_host,
        addresses=fresh,
        first=first,
        consistent=True,
        added=added,
        removed=removed,
    )


def dns_rebind_check(
    host: Any,
    first_result: Any = None,
    resolver: Callable[..., Any] | None = None,
    expected: Any = None,
    port: int | None = None,
    allow_private: bool = False,
) -> dict[str, Any]:
    """DNS 重绑定综合检查。

    首次答案可来自 ``first_result``/``expected``；缺省时在此处解析一次作为
    基线，然后再解析一次比对。两次解析必须落在同一地址集合内，且全部
    通过 CIDR 校验，否则拒绝。
    """
    normalized = _canonical_host(host)
    if not normalized:
        return _blocked("invalid_host", host=None)

    baseline = first_result if first_result is not None else expected
    if baseline is None:
        literal = _host_to_ip(normalized)
        if literal is not None:
            baseline = [str(literal)]
        else:
            baseline = _resolve(normalized, port, resolver)
        if not baseline:
            return _blocked("unresolvable", host=normalized, addresses=[])

    first = _iter_addresses(baseline)
    for address in first:
        check = cidr_block(address, block_private=not allow_private)
        if not check["ok"]:
            return _blocked(
                check.get("reason", "blocked_network"),
                host=normalized,
                first=first,
                addresses=first,
                ip=address,
                matched_network=check.get("matched_network"),
                consistent=False,
            )

    result = second_resolve(
        normalized,
        expected=first,
        resolver=resolver,
        port=port,
        allow_private=allow_private,
    )
    if not result["ok"]:
        return result
    return _allowed(
        host=normalized,
        first=first,
        addresses=result["addresses"],
        consistent=True,
        added=result.get("added", []),
        removed=result.get("removed", []),
    )


def ip_pin(
    host: Any,
    ip: Any = None,
    port: int | None = None,
    resolver: Callable[..., Any] | None = None,
    allow_private: bool = False,
    addresses: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """把连接目标固定到已校验的 IP，同时保留原 Host/SNI。

    返回的 ``connect_host`` 是字面 IP，``host_header``/``sni_hostname``
    仍是原域名。若给出 ``ip``，要求它属于该主机当前解析结果。
    ``addresses`` 可传入已校验的解析结果，避免再次 DNS 解析。
    """
    normalized = _canonical_host(host)
    if not normalized:
        return _blocked("invalid_host", host=None)

    if addresses is not None:
        resolution = _iter_addresses(addresses)
    else:
        resolution = _addresses_for(normalized, port, resolver)
    if not resolution:
        return _blocked("unresolvable", host=normalized, addresses=[])

    if ip is None:
        pinned = resolution[0]
    else:
        pinned_parsed = _normalize_ip(ip)
        if pinned_parsed is None:
            return _blocked("invalid_ip", host=normalized, ip=str(ip))
        pinned = str(pinned_parsed)
        if pinned not in resolution:
            return _blocked(
                "ip_not_in_resolution",
                host=normalized,
                ip=pinned,
                addresses=resolution,
            )

    check = cidr_block(pinned, block_private=not allow_private)
    if not check["ok"]:
        return _blocked(
            check.get("reason", "blocked_network"),
            host=normalized,
            ip=pinned,
            matched_network=check.get("matched_network"),
        )

    literal = _host_to_ip(normalized)
    host_header = normalized if literal is None else (
        f"[{normalized}]" if ":" in normalized else normalized
    )
    default_port = DEFAULT_PORTS.get("https", 443)
    return _allowed(
        host=normalized,
        ip=pinned,
        connect_host=pinned,
        host_header=host_header,
        sni_hostname=None if literal is not None else normalized,
        port=port if port is not None else default_port,
        addresses=resolution,
        pinned=True,
        family=ipaddress.ip_address(pinned).version,
    )


def validation(
    url: Any,
    resolver: Callable[..., Any] | None = None,
    allowlist: Iterable[str] | None = None,
    allow_private: bool = False,
    connect: bool = False,
    port: int | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """完整校验入口: 解析校验 + 元数据 + 二次解析（+ 可选 IP pin）。

    ``connect=True`` 时额外返回 :func:`ip_pin` 的结果，调用方可以直接用
    ``connect_host`` 建连，避免校验与连接之间再次发生 DNS 变化。
    """
    parsed = parse_and_validate(
        url,
        resolver=resolver,
        allow_private=allow_private,
        allowlist=allowlist,
        port=port,
    )
    if not parsed["ok"]:
        return parsed

    host = parsed["host"]
    first = parsed["addresses"]

    second = second_resolve(
        host, expected=first, resolver=resolver, port=parsed["port"], allow_private=allow_private
    )
    if not second["ok"]:
        return second

    result = dict(parsed)
    result["second_resolve"] = second
    result["consistent"] = True

    if connect:
        # 用首次答案固定连接目标，不再触发第三次解析。
        pinned = ip_pin(
            host,
            second["addresses"][0],
            parsed["port"],
            addresses=first,
            allow_private=allow_private,
        )
        if not pinned["ok"]:
            return pinned
        result["pin"] = pinned
        result["connect_host"] = pinned["connect_host"]
        result["host_header"] = pinned["host_header"]
        result["sni_hostname"] = pinned["sni_hostname"]
    return result


# ---------------------------------------------------------------------------
# 5. 跳转策略
# ---------------------------------------------------------------------------


def redirect_policy(
    location: Any = None,
    status_code: Any = None,
    current_url: Any = None,
    max_redirects: int = 0,
    follow: bool | None = None,
    resolver: Callable[..., Any] | None = None,
    allow_private: bool = False,
    allowlist: Iterable[str] | None = None,
) -> dict[str, Any]:
    """禁止自动跟随 3xx；显式要求时才逐跳校验后跟随。

    - 默认 ``max_redirects=0``: 只要出现 3xx 就返回 ``follow=False``，
      交由调用方处理（不把 Location 交给 HTTP 客户端自动请求）。
    - ``max_redirects > 0``: 仅当跳转目标通过 :func:`parse_and_validate`
      的完整校验才允许跟随；``location`` 可以是绝对 URL（推荐）或相对
      URL（需要 ``current_url``）。
    - ``follow=False`` 显式禁止跟随；``follow=True`` 等价于至少允许 1 跳，
      但仍要受完整校验约束。

    返回 ``allowed`` 表示"本次跳转目标是否可以被跟随"（未要求跟随时为
    ``False``，但 ``ok`` 仍为 True）。
    """
    limit = _as_int(max_redirects)
    if limit is None or limit < 0:
        return _blocked("invalid_max_redirects", follow=False)

    if follow is True and limit == 0:
        limit = 1
    if follow is False:
        limit = 0

    code = _as_int(status_code)
    is_redirect = (
        (code is not None and code in _REDIRECT_CODES)
        or (code is not None and 300 <= code < 400)
    )

    if not is_redirect:
        return _result(
            True,
            follow=False,
            allowed=False,
            is_redirect=False,
            status_code=code,
            max_redirects=limit,
            reason="not_a_redirect",
        )

    if limit <= 0:
        return _result(
            True,
            follow=False,
            allowed=False,
            is_redirect=True,
            status_code=code,
            max_redirects=limit,
            location=location,
            reason="redirect_following_disabled",
        )

    if location is None or (isinstance(location, str) and not location.strip()):
        return _blocked(
            "missing_location",
            follow=False,
            allowed=False,
            is_redirect=True,
            status_code=code,
            max_redirects=limit,
        )

    target = location.strip() if isinstance(location, str) else location
    if current_url is not None:
        base = _split_url(current_url)
        if base is not None:
            try:
                target = urllib.parse.urljoin(current_url, target)
            except ValueError:
                return _blocked("invalid_location", follow=False, allowed=False)
    elif isinstance(target, str) and not urllib.parse.urlsplit(target).scheme:
        return _blocked(
            "relative_location_without_base",
            follow=False,
            allowed=False,
            location=location,
        )

    checked = parse_and_validate(
        target,
        resolver=resolver,
        allow_private=allow_private,
        allowlist=allowlist,
    )
    if not checked["ok"]:
        return _blocked(
            checked.get("reason", "redirect_target_rejected"),
            follow=False,
            allowed=False,
            is_redirect=True,
            status_code=code,
            location=location,
            target=target,
            max_redirects=limit,
            target_error=checked,
        )

    # 307/308 必须保留原方法和请求体，301/302/303 由调用方按常见语义转 GET。
    method_override = "GET" if code in (301, 302, 303) else None
    return _allowed(
        follow=True,
        is_redirect=True,
        status_code=code,
        location=location,
        target=checked["url"],
        target_host=checked["host"],
        target_ip=checked["ip"],
        max_redirects=limit,
        remaining_redirects=limit - 1,
        method_override=method_override,
        target_check=checked,
    )


# ---------------------------------------------------------------------------
# 6. 超时与响应体限制
# ---------------------------------------------------------------------------


def timeout_guard(
    timeout: Any = None,
    connect_timeout: Any = None,
    read_timeout: Any = None,
    max_timeout: float = 30.0,
    deadline: float | None = None,
) -> dict[str, Any]:
    """强制设置连接/读取超时，并限制上限。

    返回可传给 HTTP 客户端的 ``timeout`` 以及拆分的
    ``connect_timeout``/``read_timeout``。未提供时使用
    :data:`DEFAULT_TIMEOUT`；超过 ``max_timeout`` 会被截断并标记
    ``clamped=True``。
    """
    base = _as_float(timeout)
    if timeout is not None and base is None:
        return _blocked("invalid_timeout", timeout=None)
    if base is None:
        base = DEFAULT_TIMEOUT
    if base <= 0:
        return _blocked("invalid_timeout", timeout=base)

    limit = _as_float(max_timeout)
    if limit is None or limit <= 0:
        return _blocked("invalid_max_timeout", timeout=None)

    clamped = False
    effective = min(base, limit)
    if effective != base:
        clamped = True

    c_timeout = _as_float(connect_timeout)
    r_timeout = _as_float(read_timeout)
    if connect_timeout is not None and (c_timeout is None or c_timeout <= 0):
        return _blocked("invalid_connect_timeout", timeout=None)
    if read_timeout is not None and (r_timeout is None or r_timeout <= 0):
        return _blocked("invalid_read_timeout", timeout=None)

    c_timeout = min(c_timeout if c_timeout is not None else effective, effective)
    r_timeout = min(r_timeout if r_timeout is not None else effective, effective)

    remaining = None
    if deadline is not None:
        dl = _as_float(deadline)
        if dl is None:
            return _blocked("invalid_deadline", timeout=None)
        remaining = dl - time.monotonic()
        if remaining <= 0:
            return _blocked("deadline_exceeded", timeout=None)
        effective = min(effective, remaining)
        c_timeout = min(c_timeout, effective)
        r_timeout = min(r_timeout, effective)
        clamped = True

    return _allowed(
        timeout=effective,
        connect_timeout=c_timeout,
        read_timeout=r_timeout,
        default_timeout=DEFAULT_TIMEOUT,
        clamped=clamped,
        deadline_remaining=remaining,
    )


def response_limit(
    content_length: Any = None,
    max_bytes: Any = None,
    body: Any = None,
    headers: Mapping[str, Any] | None = None,
    truncated_ok: bool = False,
) -> dict[str, Any]:
    """限制响应体大小，防止恶意服务返回无限流。

    可通过 ``content_length`` 或 ``headers``（``Content-Length``）预估；
    也可以传入已读取的 ``body`` 检查实际大小。超过 ``max_bytes`` 时默认
    拒绝（``truncated_ok=True`` 时返回截断后的 body 并标记 ``truncated``）。
    """
    limit = _as_int(max_bytes if max_bytes is not None else DEFAULT_MAX_BYTES)
    if limit is None or limit <= 0:
        return _blocked("invalid_max_bytes", limit=None)

    declared = content_length
    if declared is None and headers:
        for key, value in headers.items():
            if isinstance(key, str) and key.lower() == "content-length":
                declared = value
                break
    declared_int = _as_int(declared)
    if declared is not None and declared_int is None:
        return _blocked("invalid_content_length", limit=limit)
    if declared_int is not None and declared_int < 0:
        return _blocked("invalid_content_length", limit=limit)

    if declared_int is not None and declared_int > limit:
        return _blocked(
            "response_too_large",
            limit=limit,
            content_length=declared_int,
        )

    if body is None:
        return _allowed(limit=limit, content_length=declared_int, size=declared_int, truncated=False)

    if isinstance(body, str):
        size = len(body.encode("utf-8", "ignore"))
    elif isinstance(body, (bytes, bytearray, memoryview)):
        size = len(bytes(body))
    else:
        return _blocked("invalid_body", limit=limit)

    if size <= limit:
        return _allowed(
            limit=limit, content_length=declared_int, size=size, truncated=False, body=body
        )
    if not truncated_ok:
        return _blocked(
            "response_too_large", limit=limit, content_length=declared_int, size=size
        )
    if isinstance(body, str):
        clipped = body.encode("utf-8", "ignore")[:limit].decode("utf-8", "ignore")
    else:
        clipped = bytes(body)[:limit]
    return _allowed(
        limit=limit,
        content_length=declared_int,
        size=size,
        truncated=True,
        body=clipped,
        bytes_read=limit,
    )


# ---------------------------------------------------------------------------
# 7. 错误归类
# ---------------------------------------------------------------------------

_ERROR_MAP: dict[str, tuple[str, str]] = {
    "invalid_url": ("invalid_input", "URL 解析失败"),
    "invalid_input": ("invalid_input", "输入非法"),
    "missing_host": ("invalid_input", "缺少主机名"),
    "invalid_host": ("invalid_input", "主机名非法"),
    "invalid_port": ("invalid_input", "端口非法"),
    "invalid_ip": ("invalid_input", "IP 非法"),
    "invalid_timeout": ("invalid_input", "超时非法"),
    "invalid_max_timeout": ("invalid_input", "最大超时非法"),
    "invalid_connect_timeout": ("invalid_input", "连接超时非法"),
    "invalid_read_timeout": ("invalid_input", "读取超时非法"),
    "invalid_deadline": ("invalid_input", "deadline 非法"),
    "invalid_max_bytes": ("invalid_input", "响应上限非法"),
    "invalid_content_length": ("invalid_input", "Content-Length 非法"),
    "invalid_body": ("invalid_input", "响应体非法"),
    "invalid_location": ("invalid_input", "跳转目标非法"),
    "invalid_rounds": ("invalid_input", "解码轮次非法"),
    "invalid_encoding": ("invalid_input", "编码非法"),
    "invalid_max_redirects": ("invalid_input", "max_redirects 非法"),
    "not_an_ip_literal": ("invalid_input", "不是 IP 字面量"),
    "unresolvable": ("dns_failure", "域名无法解析"),
    "scheme_not_allowed": ("policy_violation", "协议不允许"),
    "missing_scheme": ("policy_violation", "缺少协议"),
    "host_not_allowlisted": ("policy_violation", "主机不在白名单"),
    "host_denied": ("policy_violation", "主机在黑名单"),
    "blocked_hostname": ("ssrf_blocked", "命中禁用主机名"),
    "metadata_endpoint": ("ssrf_blocked", "命中云元数据地址"),
    "metadata_hostname": ("ssrf_blocked", "命中云元数据主机名"),
    "link_local_metadata": ("ssrf_blocked", "命中链路本地地址"),
    "private_network": ("ssrf_blocked", "命中私网地址"),
    "loopback": ("ssrf_blocked", "命中环回地址"),
    "unspecified": ("ssrf_blocked", "命中未指定地址"),
    "link_local": ("ssrf_blocked", "命中链路本地地址"),
    "multicast": ("ssrf_blocked", "命中组播地址"),
    "reserved": ("ssrf_blocked", "命中保留地址"),
    "blocked_network": ("ssrf_blocked", "命中禁用网段"),
    "dns_rebinding_detected": ("dns_rebinding", "DNS 重绑定"),
    "ip_not_in_resolution": ("dns_rebinding", "固定 IP 与解析结果不一致"),
    "redirect_following_disabled": ("redirect_blocked", "禁止自动跟随跳转"),
    "missing_location": ("redirect_blocked", "跳转缺少 Location"),
    "relative_location_without_base": ("redirect_blocked", "相对跳转缺少基准 URL"),
    "redirect_target_rejected": ("redirect_blocked", "跳转目标未通过校验"),
    "response_too_large": ("response_blocked", "响应体超限"),
    "deadline_exceeded": ("timeout", "超过总时限"),
    "timeout": ("timeout", "请求超时"),
    "ssl_error": ("tls", "TLS 校验失败"),
    "connection_failed": ("network", "连接失败"),
}


def error_map(error: Any = None, code: str | None = None) -> dict[str, Any]:
    """把错误码/异常/检查结果归类，便于调用方统一处理。

    接受错误码字符串、:class:`GuardError`、任意异常，或检查函数返回的
    字典（读取其中的 ``error``/``reason``）。未知错误归为
    ``blocked=True``，保持 fail-closed。
    """
    raw_code = code
    if raw_code is None:
        if isinstance(error, GuardError):
            raw_code = error.code
        elif isinstance(error, BaseException):
            raw_code = getattr(error, "code", None) or "unknown_error"
        elif isinstance(error, Mapping):
            raw_code = error.get("error") or error.get("reason")
        elif isinstance(error, str):
            raw_code = error
    if not isinstance(raw_code, str) or not raw_code:
        raw_code = "unknown_error"

    info = _ERROR_MAP.get(raw_code)
    if info is None:
        lowered = raw_code.lower()
        if "timeout" in lowered or "timed out" in lowered:
            info = ("timeout", "请求超时")
        elif "ssl" in lowered or "certificate" in lowered:
            info = ("tls", "TLS 校验失败")
        elif "refused" in lowered or "unreachable" in lowered or "reset" in lowered:
            info = ("network", "网络错误")
        else:
            info = ("unknown_error", "未知错误")
    category, message = info
    return _result(
        False,
        code=raw_code,
        category=category,
        message=message,
        blocked=True,
    )


# ---------------------------------------------------------------------------
# 8. 实际的连接层（可选使用）
# ---------------------------------------------------------------------------


def _connect_pinned(
    address: str,
    port: int,
    timeout: float,
    source_address: Any = None,
) -> socket.socket:
    """连接到已校验的字面 IP，彻底绕开再次 DNS 解析。"""
    # 地址已是字面 IP，禁止再做任何名字解析（AI_NUMERICHOST）。
    infos = socket.getaddrinfo(
        address, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_NUMERICHOST
    )
    last_error: OSError | None = None
    for family, socktype, proto, _canon, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            if source_address is not None:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:  # pragma: no cover - 依赖真实网络
            last_error = exc
            sock.close()
    raise last_error or OSError("connection failed")


def safe_fetch(
    url: Any,
    timeout: Any = None,
    max_bytes: Any = None,
    allow_redirects: bool = False,
    max_redirects: int = 0,
    allowlist: Iterable[str] | None = None,
    allow_private: bool = False,
    resolver: Callable[..., Any] | None = None,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> dict[str, Any]:
    """带完整 SSRF 防护的 HTTP 请求。

    - 每次跳转都重新做 :func:`parse_and_validate`，并禁止底层客户端自动
      跟随（``http.client`` 本身不跟随，这里也不手工无条件跟随）。
    - 连接到通过 :func:`ip_pin` 固定的 IP，Host/SNI 使用原域名。
    - 强制超时；读取时按 ``max_bytes`` 截断/拒绝。
    """
    if allow_redirects and max_redirects <= 0:
        max_redirects = 3
    if not allow_redirects:
        max_redirects = 0

    limit = _as_int(max_bytes if max_bytes is not None else DEFAULT_MAX_BYTES)
    if limit is None or limit <= 0:
        return _blocked("invalid_max_bytes")
    clock = timeout_guard(timeout)
    if not clock["ok"]:
        return clock
    deadline = time.monotonic() + clock["timeout"]

    current_method = (method or "GET").upper()
    current_url: Any = url
    hops = 0
    history: list[str] = []

    while True:
        checked = validation(
            current_url,
            resolver=resolver,
            allowlist=allowlist,
            allow_private=allow_private,
            connect=True,
        )
        if not checked["ok"]:
            return checked

        scheme = checked["scheme"]
        host_header = checked["host_header"]
        port = checked["port"]
        target = checked["connect_host"]
        path = checked["path"] or "/"
        if checked["query"]:
            path = f"{path}?{checked['query']}"

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _blocked("deadline_exceeded", url=current_url, history=history)
        hop_timeout = min(clock["timeout"], remaining)

        request_headers = {"Host": _host_header_with_port(host_header, scheme, port)}
        request_headers["Connection"] = "close"
        if headers:
            for key, value in headers.items():
                if isinstance(key, str) and key.lower() == "host":
                    continue
                request_headers[str(key)] = str(value)

        connection: http.client.HTTPConnection | None = None
        sock = None
        try:
            sock = _connect_pinned(target, port, hop_timeout)
            if scheme == "https":
                context = ssl_context or ssl.create_default_context()
                sock = context.wrap_socket(
                    sock, server_hostname=checked.get("sni_hostname") or checked["host"]
                )
            connection = http.client.HTTPConnection(target, port, timeout=hop_timeout)
            connection.sock = sock
            sock = None
            connection.request(current_method, path, headers=request_headers)
            response = connection.getresponse()
            status = response.status
            response_headers = dict(response.getheaders())
            location = response.getheader("Location")

            if 300 <= status < 400:
                # 跳转目标必须重新走完整校验；默认 max_redirects=0 时直接拒绝。
                decision = redirect_policy(
                    location,
                    status,
                    current_url,
                    max_redirects=max_redirects,
                    allow_private=allow_private,
                    allowlist=allowlist,
                    resolver=resolver,
                )
                if not decision["ok"] or not decision.get("follow"):
                    return _result(
                        False,
                        error=decision.get("reason", "redirect_blocked"),
                        allowed=False,
                        blocked=True,
                        status=status,
                        location=location,
                        url=current_url,
                        history=history,
                        body=None,
                    )
                hops += 1
                history.append(current_url)
                current_url = decision["target"]
                if status == 303 or (
                    status in (301, 302) and current_method not in ("GET", "HEAD")
                ):
                    current_method = "GET"
                max_redirects -= 1
                continue

            declared = response.getheader("Content-Length")
            declared_int = _as_int(declared)
            if declared_int is not None and declared_int > limit:
                # 声明超限: 不读取完整响应体，只取限长前缀。
                raw = response.read(limit)
                body = raw
                truncated = True
            else:
                raw = response.read(limit + 1)
                limited = response_limit(
                    content_length=declared,
                    max_bytes=limit,
                    body=raw,
                    truncated_ok=True,
                )
                if limited["ok"]:
                    body = limited.get("body", b"")
                    truncated = bool(limited.get("truncated", False))
                else:
                    body = raw[:limit]
                    truncated = True
            return _allowed(
                url=current_url,
                status=status,
                headers=response_headers,
                body=body,
                size=len(body),
                truncated=truncated,
                history=history,
            )
        except (socket.timeout, TimeoutError):
            return _blocked("timeout", url=current_url, history=history)
        except ssl.SSLError as exc:
            return _blocked("ssl_error", url=current_url, detail=str(exc), history=history)
        except OSError as exc:
            return error_map("connection_failed", code="connection_failed") | {
                "detail": str(exc),
                "url": current_url,
            }
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except Exception:  # pragma: no cover
                    pass


def _host_header_with_port(host_header: str, scheme: str, port: int) -> str:
    default = DEFAULT_PORTS.get(scheme)
    if default == port:
        return host_header
    return f"{host_header}:{port}"
