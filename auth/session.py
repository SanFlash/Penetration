"""
auth/session.py — log in as a test account and return a requests.Session
with the resulting cookies attached, for use by scanners that need an
authenticated context (e.g. scanners/idor_probe.py).
"""
import requests

from utils.scope import assert_in_scope


def login(base_url: str, username: str, password: str) -> requests.Session:
    login_url = f"{base_url}/login"
    assert_in_scope(login_url)
    session = requests.Session()
    resp = session.post(login_url, data={"username": username, "password": password}, timeout=10)
    resp.raise_for_status()
    return session
