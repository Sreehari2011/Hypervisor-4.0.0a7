import subprocess,json
subprocess.run(["python3","run/build_report.py"])
r=json.load(open("final_report.json"))
m=json.load(open("run/findings.json"))
assert len(r["findings"])==len(m["findings"]), "count mismatch"
print("PASS parse+count:",len(r["findings"]),"sev",r["summary"]["counts_by_severity"])
