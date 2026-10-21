import sys, urllib.request, urllib.parse, re

BASE = "http://10.31.0.87:3000"

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
ck_in = "; ".join("%s=%s" % kv for kv in cookies.items())

data = urllib.parse.urlencode({"username": "admin", "password": "password", "Login": "Login", "user_token": tok}).encode()
req = urllib.request.Request(BASE + "/login.php", data=data, method="POST")
req.add_header("Cookie", ck_in)
try:
    r = op.open(req, timeout=15)
    loc = "(none)"
    extra = r.headers.get_all("Set-Cookie") or []
except urllib.error.HTTPError as exc_obj:
    loc = exc_obj.headers.get("Location")
    extra = exc_obj.headers.get_all("Set-Cookie") or []
for c in extra:
    k, v = c.split(";")[0].split("=", 1)
    if k == "PHPSESSID":
        cookies[k] = v
if loc and "login.php" not in str(loc):
    sys.stdout.write("; ".join("%s=%s" % kv for kv in cookies.items()) + " | OK loc=" + str(loc) + "\n")
else:
    sys.stdout.write("FAIL " + str(loc) + "\n")
