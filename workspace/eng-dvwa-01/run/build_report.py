#!/usr/bin/env python3
import json, os, datetime
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

with open(os.path.join(ROOT,"report_manifest.json")) as f: man = json.load(f)
with open(os.path.join(ROOT,"run/findings.json")) as f: findings = json.load(f)["findings"]

descriptions = man.get("findings_description",{})
remediation = {
 "CWE-78":"Strict input validation use OS-level APIs instead of shell; whitelist of expected values.",
 "CWE-89":"Parameterized queries/Prepared statements; least-privilege DB user.",
 "CWE-22":"Reject all user-controlled file paths; use allow-list of templates/pages.",
 "CWE-434":"Validate content-type/extension/MIME; store outside web root; random names; no double extension.",
 "CWE-79":"Context-aware output encoding; CSP; sanitize input; frameworks that autoescape.",
 "CWE-352":"User-specific session-bound CSRF tokens; SameSite=Lax/Strict cookies.",
 "CWE-287":"Enforce server-side CAPTCHA validation; unique session-bound tokens; rotate on error.",
 "CWE-601":"Allowlist of destination URLs / disallow offsite redirects for GET.",
 "CWE-384":"Strong random session IDs; rotate after login; bind to UA/IP.",
 "CWE-521":"Enforce strong password policy; MFA; rate limit; hash modern bcrypt/argon2.",
 "CWE-209":"Remove X-Powered-By, server tokens; deny access to phpinfo; security headers.",
 "CWE-367":"Atomic operations / pessimistic locking; unique token per request.",
 "CWE-306":"AuthN/AuthZ on all REST endpoints; audit non-idempotent PUT/DELETE."
}
references = {
 "CWE-78":["https://cwe.mitre.org/data/definitions/78.html"],
 "CWE-89":["https://cwe.mitre.org/data/definitions/89.html","https://owasp.org/www-community/attacks/SQL_Injection"],
 "CWE-22":["https://cwe.mitre.org/data/definitions/22.html"],
 "CWE-434":["https://cwe.mitre.org/data/definitions/434.html"],
 "CWE-79":["https://cwe.mitre.org/data/definitions/79.html","https://owasp.org/www-community/xss"],
 "CWE-352":["https://cwe.mitre.org/data/definitions/352.html","https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
 "CWE-287":["https://cwe.mitre.org/data/definitions/287.html","OWASP AT-8: Bypassing authentication"],
 "CWE-601":["https://cwe.mitre.org/data/definitions/601.html"],
 "CWE-384":["https://cwe.mitre.org/data/definitions/384.html"],
 "CWE-521":["https://cwe.mitre.org/data/definitions/521.html","https://owasp.org/www-community/password-special-characters"],
 "CWE-209":["https://cwe.mitre.org/data/definitions/209.html","OWASP G-SEC-5"],
 "CWE-367":["https://cwe.mitre.org/data/definitions/367.html"],
 "CWE-306":["https://cwe.mitre.org/data/definitions/306.html"]
}

findings_out = []
for f in findings:
    cwe = f["class"]
    findings_out.append({**f,
      "description": descriptions.get(f["id"], f["title"]),
      "remediation": remediation.get(cwe,"Follow defense-in-depth guidance."),
      "references": references.get(cwe,[])
    })

sev={}
for f in findings_out: sev[f["severity"]]=sev.get(f["severity"],0)+1
summary=dict(man["summary"]); summary["counts_by_severity"]=sev
report = {
 "engagement": man["engagement_meta"],
 "summary": summary,
 "findings": findings_out,
 "chains": man["chains"],
 "novel_findings": man["novel_findings"],
 "negative_results": man["negative_results"],
 "out_of_scope_observations": [
   {"observation":"Scope limited to http://10.31.0.87:3000 only. No adjacent hosts/services tested (even in bounds)","when":"15-16 Oct 2026"}
 ],
 "appendix": {
   "tool_versions": {"bash":"linux","curl":"system","python":"3.x","sqlmap":"(installed)","hydra":"(installed)"},
   "notes":["Run 3 closed only Captcha item (still partial/suspected).",
            "Evidence captured in evidence/ subdirectories prior + run 3.",
            "compile_report (markdown) emitted separately at report.md"]
 }
}
with open(os.path.join(ROOT,"final_report.json"),"w") as f:
    json.dump(report, f, indent=2)
print("WROTE", os.path.join(ROOT,"final_report.json"), "findings=", len(findings_out))
