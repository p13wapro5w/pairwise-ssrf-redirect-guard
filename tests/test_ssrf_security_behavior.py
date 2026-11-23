"""SSRF 防护的行为级回归测试（不访问真实网络）。

覆盖攻击面: legacy IPv4 写法、主机名编码、CIDR 内网段、元数据端点、
默认不跟随跳转、DNS 重绑定、IP pin、响应体与超时限制。
"""

import pytest

import security.ssrf_redirect_guard as mod

PUBLIC = ["93.184.216.34"]


def resolver_public(host, port=None):
    return list(PUBLIC)


def resolver_factory(*answers):
    """依次返回给定的答案列表，用于模拟 DNS 重绑定。"""
    queue = [list(a) for a in answers]

    def resolve(host, port=None):
        return queue.pop(0) if queue else answers[-1]

    return resolve


# ---------------------------------------------------------------------------
# 字面 IP 归一化
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host,expected",
    [
        ("0177.0.0.1", "127.0.0.1"),
        ("0x7f.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("017700000001", "127.0.0.1"),
        ("0xA9FEA9FE", "169.254.169.254"),
        ("0251.0376.0251.0376", "169.254.169.254"),
        ("0300.0250.0341.0376", "192.168.225.254"),
    ],
)
def test_octal_ip_normalize(host, expected):
    result = mod.octal_ip_normalize(host)
    assert result["ok"] is True
    assert result["normalized"] == expected
    assert result["is_ip"] is True


@pytest.mark.parametrize("host", ["1.2.3.4.5", "example.com", "4294967296", "1e2", "+127.0.0.1"])
def test_octal_ip_normalize_rejects_non_literals(host):
    assert mod.octal_ip_normalize(host)["ok"] is False


# ---------------------------------------------------------------------------
# CIDR / 元数据
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip,reason",
    [
        ("127.0.0.1", "loopback"),
        ("10.1.2.3", "private_network"),
        ("172.20.0.1", "private_network"),
        ("192.168.1.1", "private_network"),
        ("100.64.0.1", "blocked_network"),
        ("169.254.1.1", "link_local"),
        ("0.0.0.0", "unspecified"),
        ("224.0.0.1", "multicast"),
        ("::1", "loopback"),
        ("fc00::1", "private_network"),
        ("fe80::1", "link_local"),
        ("::ffff:10.0.0.1", "private_network"),
        ("2002:7f00:1::", "loopback"),
    ],
)
def test_cidr_block_rejects_internal(ip, reason):
    result = mod.cidr_block(ip)
    assert result["ok"] is False
    assert result["reason"] == reason


@pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "2606:2800:220:1::1"])
def test_cidr_block_allows_public(ip):
    assert mod.cidr_block(ip)["ok"] is True


def test_cidr_block_allow_private_still_blocks_metadata():
    assert mod.cidr_block("10.0.0.5", allow_private=True)["ok"] is True
    assert mod.cidr_block("169.254.169.254", allow_private=True)["reason"] == "metadata_endpoint"
    assert mod.cidr_block("fe80::1", allow_private=True)["reason"] == "link_local"


@pytest.mark.parametrize("target", ["169.254.169.254", "http://169.254.169.254/", "http://[fd00:ec2::254]/"])
def test_metadata_block(target):
    assert mod.metadata_block(target)["reason"] == "metadata_endpoint"


def test_metadata_block_hostname():
    result = mod.metadata_block("http://metadata.google.internal/", resolver=resolver_public)
    assert result["reason"] == "metadata_hostname"


# ---------------------------------------------------------------------------
# URL 解析后校验
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://0177.0.0.1/",
        "http://0x7f.1/",
        "http://2130706433/",
        "http://127.1/",
        "http://127.0.0.1./",
        "http://%31%32%37.0.0.1/",
        "http://localhost/",
        "http://LOCALHOST./",
        "http://１０．０．０．１/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/",
        "http://user:pass@169.254.169.254/",
        "http://example.com@127.0.0.1/",
        "http://192.168.1.1\\@example.com/",
        "http://0/",
        "http://10.0.0.5/",
        "http://100.64.0.1/",
        "gopher://127.0.0.1:6379/_x",
        "file:///etc/passwd",
    ],
)
def test_parse_and_validate_blocks_attacks(url):
    result = mod.parse_and_validate(url, resolver=resolver_public)
    assert result["ok"] is False
    assert result["allowed"] is False


def test_parse_and_validate_allows_public():
    result = mod.parse_and_validate("https://example.com/x", resolver=resolver_public)
    assert result["ok"] is True
    assert result["ip"] == "93.184.216.34"
    assert result["port"] == 443


def test_parse_and_validate_fail_closed_on_mixed_answers():
    """DNS 返回公网+私网混合时不能只看第一个地址。"""
    result = mod.parse_and_validate(
        "http://example.com/", resolver=lambda h, p=None: ["93.184.216.34", "127.0.0.1"]
    )
    assert result["ok"] is False


def test_parse_and_validate_unresolvable():
    assert mod.parse_and_validate("http://example.com/", resolver=lambda h, p=None: [])["ok"] is False


# ---------------------------------------------------------------------------
# 跳转策略
# ---------------------------------------------------------------------------


def test_redirect_not_followed_by_default():
    result = mod.redirect_policy("/next", 302, "https://example.com/a", resolver=resolver_public)
    assert result["ok"] is True
    assert result["follow"] is False
    assert result["reason"] == "redirect_following_disabled"


def test_redirect_to_metadata_rejected_even_when_allowed():
    result = mod.redirect_policy(
        "http://169.254.169.254/",
        302,
        "https://example.com/a",
        max_redirects=3,
        resolver=resolver_public,
    )
    assert result["ok"] is False
    assert result["follow"] is False


def test_redirect_relative_requires_base():
    result = mod.redirect_policy("/next", 302, max_redirects=1, resolver=resolver_public)
    assert result["ok"] is False
    assert result["follow"] is False


def test_redirect_follow_valid_target():
    result = mod.redirect_policy(
        "/b", 303, "https://example.com/a", max_redirects=2, resolver=resolver_public
    )
    assert result["ok"] is True
    assert result["follow"] is True
    assert result["target"] == "https://example.com/b"
    assert result["method_override"] == "GET"


def test_non_redirect_status_is_not_followed():
    result = mod.redirect_policy("https://example.com/b", 200, max_redirects=3)
    assert result["ok"] is True
    assert result["follow"] is False


# ---------------------------------------------------------------------------
# DNS 重绑定 / 二次解析 / IP pin
# ---------------------------------------------------------------------------


def test_second_resolve_detects_rebinding():
    result = mod.second_resolve(
        "evil.example", expected=PUBLIC, resolver=lambda h, p=None: ["93.184.216.35"]
    )
    assert result["ok"] is False
    assert result["reason"] == "dns_rebinding_detected"
    assert result["added"] == ["93.184.216.35"]


def test_second_resolve_detects_private_rebind():
    result = mod.dns_rebind_check(
        "evil.example", first_result=PUBLIC, resolver=lambda h, p=None: ["127.0.0.1"]
    )
    assert result["ok"] is False


def test_second_resolve_consistent():
    result = mod.second_resolve("example.com", expected=PUBLIC, resolver=resolver_public)
    assert result["ok"] is True
    assert result["consistent"] is True


def test_validation_rejects_rebinding():
    flip = resolver_factory(PUBLIC, ["93.184.216.35"])
    result = mod.validation("http://evil.example/", resolver=flip)
    assert result["ok"] is False
    assert result["reason"] == "dns_rebinding_detected"


def test_ip_pin_keeps_host_header():
    result = mod.ip_pin("example.com", addresses=PUBLIC)
    assert result["ok"] is True
    assert result["connect_host"] == "93.184.216.34"
    assert result["host_header"] == "example.com"
    assert result["sni_hostname"] == "example.com"


def test_ip_pin_rejects_ip_outside_resolution():
    result = mod.ip_pin("example.com", "93.184.216.99", addresses=PUBLIC)
    assert result["ok"] is False
    assert result["reason"] == "ip_not_in_resolution"


def test_ip_pin_rejects_private():
    assert mod.ip_pin("example.com", addresses=["10.0.0.1"])["ok"] is False


# ---------------------------------------------------------------------------
# 其余检查
# ---------------------------------------------------------------------------


def test_allow_scheme():
    assert mod.allow_scheme("https://example.com")["ok"] is True
    assert mod.allow_scheme("http://example.com")["ok"] is True
    assert mod.allow_scheme("file:///etc/passwd")["ok"] is False
    assert mod.allow_scheme("gopher://example.com")["ok"] is False
    assert mod.allow_scheme("")["ok"] is False


def test_url_decode_once():
    assert mod.url_decode_once("%31%32%37.0.0.1")["decoded"] == "127.0.0.1"


def test_host_allowlist():
    assert mod.host_allowlist("a.example.com", allowlist=["*.example.com"])["ok"] is True
    assert mod.host_allowlist("example.com", allowlist=["*.example.com"])["ok"] is True
    assert mod.host_allowlist("evil.com", allowlist=["*.example.com"])["ok"] is False
    assert mod.host_allowlist("evil.com", allowlist=["*.example.com"], deny=["evil.com"])["ok"] is False
    assert mod.host_allowlist("127.0.0.1", allowlist=["127.0.0.0/8"])["ok"] is True


def test_timeout_guard():
    default = mod.timeout_guard()
    assert default["timeout"] == mod.DEFAULT_TIMEOUT
    clamped = mod.timeout_guard(999)
    assert clamped["ok"] is True and clamped["clamped"] is True
    assert clamped["timeout"] == clamped["connect_timeout"]
    assert mod.timeout_guard(-1)["ok"] is False


def test_response_limit():
    assert mod.response_limit(headers={"Content-Length": "10"}, max_bytes=5)["ok"] is False
    assert mod.response_limit(body=b"x" * 10, max_bytes=5)["ok"] is False
    truncated = mod.response_limit(body=b"x" * 10, max_bytes=5, truncated_ok=True)
    assert truncated["ok"] is True and truncated["truncated"] is True
    assert truncated["body"] == b"xxxxx"


def test_error_map():
    assert mod.error_map("dns_rebinding_detected")["category"] == "dns_rebinding"
    assert mod.error_map("metadata_endpoint")["category"] == "ssrf_blocked"
    assert mod.error_map("something weird")["blocked"] is True
