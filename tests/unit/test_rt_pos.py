import json
import re

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from mcp_toolbox.redaction.service import Redactor

R = Redactor()
val = st.text(
    st.characters(
        min_codepoint=32, max_codepoint=0x2FFF, blacklist_categories=("Cs", "Zl", "Zp", "Cc")
    ),
    min_size=1,
    max_size=30,
).filter(lambda s: s.strip() == s)
KEYS = [
    "password",
    "PWD",
    "db_password",
    "client_secret",
    "api_key",
    "x-api-key",
    "token",
    "access_token",
]


@settings(max_examples=3000, suppress_health_check=list(HealthCheck), deadline=None)
@given(v=val, k=st.sampled_from(KEYS), f=st.sampled_from(["kv", "kvs", "colon", "json", "env"]))
def test_value_position(v, k, f):
    pre = {
        "kv": f"{k}=",
        "kvs": f"{k} = ",
        "colon": f"{k}: ",
        "json": f'{{"{k}": "',
        "env": f"export {k.upper()}=",
    }[f]
    body = json.dumps(v)[1:] + "}" if f == "json" else v
    text = pre + body
    out = R.redact(text).text
    assert out.startswith(pre), (text, out)
    rest = re.sub(r"\[REDACTED_[A-Z_]+\]", "", out[len(pre) :], count=1)
    assert out[len(pre) :] != rest and set(rest) <= set('"}'), (text, out)
