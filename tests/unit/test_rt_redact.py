import json
import re
import urllib.parse

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from mcp_toolbox.redaction.service import Redactor

R = Redactor()
KEYS = (
    "db_password",
    "client_secret",
    "password",
    "api_key",
    "token",
    "pwd",
    "postgres://u:",
    "@db.local:5432/x",
    "https://user:",
    "@host/",
)


def visible(out):
    # Markers and the key/URL scaffolding are not secret text; a short secret such as "a" also
    # appears in "password", so judge leaks only on what is left once those are removed.
    out = re.sub(r"\[REDACTED_[A-Z_]+\]", "\x00", out)
    for key in KEYS:
        out = out.replace(key, "\x00")
    return out


def leaks(secret, out):
    return [secret[i : i + 4] for i in range(len(secret) - 3) if secret[i : i + 4] in out]


CASES = [
    ("password=abc", "abc"),
    ("password: a", "a"),
    ('{"password": "ab"}', "ab"),
    ("password: my secret pass", "my secret pass"),
    ('password="a b,c{d}\\"e"', 'a b,c{d}\\"e'),
    ("password=[REDACTED_X]realsecret", "realsecret"),
    ('password="[REDACTED_X]realsecret"', "realsecret"),
    ("client_secret=abc123", "abc123"),
    ("client_secret=[REDACTED_A]supersecret", "supersecret"),
    ("token=abcdefghijkl!MNOPQRsecret", "MNOPQRsecret"),
    ("api_key=short", "short"),
    ("password: 'it''sasecret'", "sasecret"),
    ("password=abcd efgh", "efgh"),
    ("https://user:p@ss word@host/", "p@ss word"),
    ("pwd = hunter2;rest", "hunter2"),
]


@pytest.mark.parametrize("text,secret", CASES)
def test_known(text, secret):
    out = visible(R.redact(text).text)
    assert secret not in out and not leaks(secret, out), out


alpha = st.text(
    st.characters(codec="ascii", min_codepoint=33, max_codepoint=126), min_size=1, max_size=24
)


@settings(max_examples=3000, suppress_health_check=list(HealthCheck), deadline=None)
@given(
    secret=alpha,
    key=st.sampled_from(["password", "pwd", "client_secret", "api_key", "token", "db_password"]),
    fmt=st.sampled_from(["kv", "json", "yaml", "url"]),
)
def test_fuzz(secret, key, fmt):
    if fmt == "kv":
        text = f"{key}={secret}"
    elif fmt == "json":
        text = json.dumps({key: secret})
    elif fmt == "yaml":
        text = f"{key}: {json.dumps(secret)}"
    else:
        text = f"postgres://u:{urllib.parse.quote(secret, safe='')}@db.local:5432/x"
        secret = urllib.parse.quote(secret, safe="")
    encoded = {"kv": secret, "url": secret}.get(fmt, json.dumps(secret)[1:-1])
    before, _, after = text.rpartition(encoded)
    skeleton = before + "\x00" + after  # the input with the value itself removed
    out = re.sub(r"\[REDACTED_[A-Z_]+\]", "\x00", R.redact(text).text)
    # Judge leaks only on secret text the output has beyond what the key and punctuation
    # already contain (a secret like ":" or "a" also appears in '"password": ').
    pieces = {secret} | {secret[i : i + 4] for i in range(len(secret) - 3)}
    assert all(out.count(p) <= skeleton.count(p) for p in pieces), (text, out)
