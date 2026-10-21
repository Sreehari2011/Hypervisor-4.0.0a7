CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=low'
B='http://10.31.0.87:3000'
curl -s -b "$CK" "$B/phpinfo.php" -o evidence/srv/phpinfo.html
grep -oE '<h1 class="p">PHP Version [^<]*' evidence/srv/phpinfo.html | head -1
curl -s -b "$CK" "$B/setup.php" -o evidence/srv/setup.html
grep -oE 'Database:|Operating System:|PHP function (safe_mode|allow_url_include)|Web Server' evidence/srv/setup.html | head -12
curl -s -b "$CK" "$B/security.txt" -o evidence/srv/security-txt -o /dev/null -w 'security.txt:%{http_code}\n'
curl -s -b "$CK" "$B/security.txt" -o evidence/srv/security-txt -w 'security.txt:%{http_code} %{size_download}\n'; head -c 300 evidence/srv/security-txt