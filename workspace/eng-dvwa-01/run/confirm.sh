# Confirm phpinfo/setup anonymous access (follow redirects)
CK=''
B='http://10.31.0.87:3000'
for U in /phpinfo.php /setup.php; do
  curl -Ls -o /dev/null -w "$U anonymous=%{http_code}\n" "$B$U"
done
