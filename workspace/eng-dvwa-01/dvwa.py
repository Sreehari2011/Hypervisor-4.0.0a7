#!/usr/bin/env python3
"""AEGIS DVWA helper: authenticated session, level control, request/response evidence capture."""
import urllib.request, urllib.parse, re, json, os, sys

BASE = "http://10.31.0.87:3000"
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "session.json")

op = urllib.request.build_opener()  # default: follows redirects

def _load():
    try:
        return json.load(open(STATE_FILE))
    except Exception:
        return {}

def _save(st):
    json.dump(st, open(STATE_FILE, "w"))

def login(force=False):
    st = _load()
    if st.get("ck") and not force:
        return st["ck"]
    s, page = fetch("/login.php", st=st)
    tok = re.search(r"user_token' value='([0-9a-f]+)'", page).group(1)
    data = urllib.parse.urlencode({
        "username": "admin", "password": "password",
        "Login": "Login", "user_token": tok}).encode()
    s, page = fetch("/login.php", data, st)
    _save(st)
    return st["ck"]

def fetch(path, data=None, st=None, extra_headers=None):
    if st is None:
        st = _load()
    req = urllib.request.Request(BASE + path, data=data)
    req.add_header("User-Agent", "AEGIS-VAPT/1.0")
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    if st.get("ck"):
        req.add_header("Cookie", st["ck"])
    try:
        resp = op.open(req)
    except urllib.error.HTTPError as e:
        resp = e
    oi = resp.info()
    raw_hdr = str(oi)
    m = re.search(r"Set-Cookie: ([^\r\n]+)", raw_hdr)
    sc = oi.get_all("Set-Cookie") or []
    if sc:
        st["ck"] = "; ".join(c.split(";")[0].strip() for c in sc)
        _save(st)
    body = resp.read().decode("utf-8", "replace")
    return resp.status, body

def set_level(level):
    login()
    s, page = fetch("/security.php")
    tok = re.search(r"user_token' value='([0-9a-f]+)'", page).group(1)
    data = urllib.parse.urlencode({
        "security": level, "seclev_submit": "Submit", "user_token": tok}).encode()
    fetch("/security.php", data)
    return _load()["ck"]

def get_token_from(page):
    m = re.search(r"user_token' value='([0-9a-f]+)'", page)
    return m.group(1) if m else None

def evid(classname, name, req_lines, resp_body, notes, status=None):
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "evidence", classname, name)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "request.txt"), "w").write(req_lines)
    open(os.path.join(d, "response.txt"), "w").write(resp_body)
    open(os.path.join(d, "notes.md"), "w").write(notes + (f"\nstatus: {status}\n" if status else ""))
    return d

if __name__ == "__main__":
    ck = login()
    print("OK session:", ck)
