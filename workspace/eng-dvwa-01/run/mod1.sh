CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
B='http://10.31.0.87:3000'
mkdir -p evidence/misc evidence/api evidence/weakid evidence/redirect

# weak_sesssion_id module
for L in low medium high impossible; do
  echo "== weak_id $L"
  curl -s -b "$CK; security=$L" "$B/vulnerabilities/weak_id/" -o /dev/null -c /tmp/wk_$L -w '%{http_code}\n'
  grep -oE 'dvwaSession\t[^\n]*' /tmp/wk_$L
done

# authbypass — bypasses content page; test direct URL as anonymous then as admin
for L in low medium high; do
  echo "== authbypass $L"
  curl -s -b "$CK; security=$L" "$B/vulnerabilities/authbypass/" -o /dev/null -w '%{http_code}\n'
  curl -s -b "$CK; security=$L" "$B/vulnerabilities/authbypass/?id=1" | grep -oE '<pre>[^<]*</pre>|User|Forbidden' | head -3
done

# javascript module
echo "== javascript"
curl -s -b "$CK; security=low" "$B/vulnerabilities/javascript/" | grep -n -E 'function|token|value|phrase' | head -15

# api
echo "== api"
curl -s -b "$CK; security=low" "$B/vulnerabilities/api/" | grep -n -E 'api|GET|POST|location' | head -10

# open_redirect
echo "== redirect"
curl -s -b "$CK; security=low" "$B/vulnerabilities/open_redirect/" | grep -n -E 'redirect|location|link' | head -10

# captcha
echo "== captcha"
curl -s -b "$CK; security=low" "$B/vulnerabilities/captcha/" | grep -n -E 'g-recaptcha|step|change' | head -10
