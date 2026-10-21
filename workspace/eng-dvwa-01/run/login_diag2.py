import sys, urllib.request, urllib.parse, re

BASE = "http://10.31.0.87:3000"

op = urllib.request.build_opener()
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
print("cookie:", ck)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

op2 = urllib.request.build_opener(NoRedirect)
data = urllib.parse.urlencode({"username": "admin", "password": "password", "Login": "Login", "user_token": tok}).encode()
req = urllib.request.Request(BASE + "/login.php", data=data, method="POST")
req.add_header("Cookie", ck)
req.add_header("User-Agent", "Mozilla/5.0")
try:
    r = op2.open(req, timeout=15)
    print("status 200:", r.read().decode()[:500])
except urllib.error.HTTPError as exc:
    print("status:", getattr(exc, "code", None), "loc:", exc.headers.get("Location"))
    tb = exc.read().decode("utf-8", "replace")
    print("body:", tb[:500])

# Follow login.php GET with same cookie
op3 = urllib.request.build_opener()
req3 = urllib.request.Request(BASE + "/login.php")
req3.add_header("Cookie", ck)
b3 = op3.open(req3, timeout=15).read().decode("utf-8", "replace")
print("GET login.php after post; len", len(b3))
for pat in ["Login failed", "CSRF", "user_token", "locked", "attempts"]:
    m = re.search(pat + r".{0,80}", b3, re.I | re.S)
    print(pat, "->", (m.group(0).replace("\n", " ")[:120] if m else "ABSENT"))
