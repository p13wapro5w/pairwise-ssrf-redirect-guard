import pytest
import security.ssrf_redirect_guard as mod

CASES = [
    ("parse_and_validate", (1, 2)),
    ("octal_ip_normalize", (1, 2)),
    ("dns_rebind_check", (1, 2)),
    ("cidr_block", (1, 2)),
    ("redirect_policy", (1, 2)),
    ("metadata_block", (1, 2)),
    ("second_resolve", (1, 2)),
    ("allow_scheme", (1, 2)),
    ("timeout_guard", (1, 2)),
    ("url_decode_once", (1, 2)),
    ("host_allowlist", (1, 2)),
    ("ip_pin", (1, 2)),
    ("response_limit", (1, 2)),
    ("error_map", (1, 2)),
    ("validation", (1, 2)),
]

@pytest.mark.parametrize("fn_name,args", CASES)
def test_contract(fn_name, args):
    fn = getattr(mod, fn_name)
    assert fn(*args) is not None
