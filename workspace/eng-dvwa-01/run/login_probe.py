import urllib.request
import urllib.parse
import re
import sys

BASE = "http://10.31.0.87:3000"
op1 = urllib.request.build_opener()
pg = op1.open(BASE + "/login.php", timeout=15)
setcookie = pg.headers.get_all("Set-Cookie") or []
body = pg.read().decode()
tok = re.search(r"user_token' value='([0-9a-f]+)'", body).group(1)
ck = "; ".join(c.split(";")[0] for c in setcookie)
sys.stdout.write("anon cookies: " + ck + "\n")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

ldap_mod = ""  # placeholder to keep names simple
data = urllib.parse.urlencode({"username": "admin", "password": "password", "Login": "Login", "user_token": tok}).encode()
op2 = urllib.request.build_opener(NoRedirect)
req = urllib.request.Request(BASE + "/login.php", data=data, method="POST")
req.add_header("Cookie", ck)
req.add_header("User-Agent", "Mozilla/5.0")
try:
    r = op2.open(req, timeout=15)
    _status = getattr(r, "status", None)
    loc = "(no redirect)"
    sc = r.headers.get_all("Set-Cookie")
except urllib.error.HTTPError as exc:
    _status = getattr(exc, "code", None)
    loc = exc.headers.get("Location")
    sc = exc.headers.get_all("Set-Cookie")
sys.stdout.write("status: %s | location: %s\n" % (_status, loc))
sys.stdout.write("set-cookie: %s\n" % sc)
