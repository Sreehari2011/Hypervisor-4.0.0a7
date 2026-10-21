CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
B='http://10.31.0.87:3000'
mkdir -p evidence/misc evidence/srv

# CSP reflection check (verify src is in page)
grep -oE "<script src='http://10\.31\.0\.87:3000/dvwa/css/main\.css" evidence/misc/csp-low-include.html | head -2

# save csp evidence
curl -s -b "$CK; security=low" "$B/vulnerabilities/csp/" -d 'include=http://10.31.0.87:3000/dvwa/css/main.css&submit=Include' -o evidence/misc/csp-reflect-low.html
grep -c "10.31.0.87:3000/dvwa/css/main.css" evidence/misc/csp-reflect-low.html

# port 80 nginx index — confirm default welcome page (a misconfig)
curl -s http://10.31.0.87:80/ -o evidence/srv/nginx-80-index.html
grep -oE '<title>[^<]*' evidence/srv/nginx-80-index.html

# OPTIONS / TRACE / TRACE disclosure
curl -s -X TRACE -b "$CK" "$B/" -o /dev/null -w 'TRACE:%{http_code}\n'
curl -s -X OPTIONS -b "$CK" "$B/" -D - -o /dev/null | head -10
