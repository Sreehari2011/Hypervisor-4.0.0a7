import json,os
sub="import subprocess; subprocess.run(['python3','run/build_report.py'])"
exec(sub)
r=json.load(open("final_report.json"))
print("parse ok; findings=%d negatives=%d chains=%d novel=%d"%(len(r["findings"]),len(r["negative_results"]),len(r["chains"]),len(r["novel_findings"])))
sev={}
for f in r["findings"]: sev[f["severity"]]=sev.get(f["severity"],0)+1
print("sev:",sev)
print("classes:",sorted({f["class"] for f in r["findings"]}))
