CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
B='http://10.31.0.87:3000'
mkdir -p evidence/crypto evidence/misc

curl -s -b "$CK; security=low" -X POST "$B/vulnerabilities/cryptography/" \
  --data-urlencode 'direction=decode' \
  --data-urlencode 'message=Lg4WGlQZChhSFBYSEB8bBQtPGxdNQSwEHREOAQY=' \
  --data-urlencode 'submit=Submit' -o evidence/crypto/xor-decode-low-response.html
grep -oE 'new password is: [^<]+' evidence/crypto/xor-decode-low-response.html

# CSP include with in-scope target URL only (scope keeps us legal)
curl -s -b "$CK; security=low" "$B/vulnerabilities/csp/" \
  -d 'include=http://10.31.0.87:3000/dvwa/css/main.css&submit=Include' \
  -o evidence/misc/csp-low-include.html
grep -oE '<script src=["'"'"'][^"'"'"']*' evidence/misc/csp-low-include.html | head -5
