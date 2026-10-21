# Port 8080 identification attempts
# Target: dppmsserchhip.mizoram.gov.in:8080  (in-scope parent domain)
#
# nmap -sT marks 8080/tcp open; -sV fingerprint placeholder: "http-proxy?"
# Proxychains tool-path interaction results (all scoped):
#  GET http://dppmsserchhip.mizoram.gov.in:8080/                       -> remote closed w/o response
#  GET http://dppmsserchhip.mizoram.gov.in:8080/  (UA header)          -> remote closed w/o response
#  GET http://dppmsserchhip.mizoram.gov.in:8080/.well-known/openid-configuration -> remote closed w/o response
#
# Interpretation: port accepts TCP but terminates on plain HTTP/1.1 and on the
# OIDC discovery path. Behavior is consistent with a TLS-only or protocol-specific
# listener (e.g. ADFS/Web-Application-Proxy style) sitting behind nginx, but the
# absolute identity cannot be confirmed from the available probe path.
# No banner, no version string, no API surface was extracted -> record as
# "unidentified service, exposure=unknown".
#
# Port 5060 SIP note:
#  - proxychains4-confined /dev/tcp GET/OPTIONS to 5060 fails at the proxy with
#    "Strict chain ... 139.84.217.111:5878 ... timeout / Connection refused"
#    (evidence: evidence/sip_options_probe.txt).
#  - nmap connect-scan sees it open, but no proxied session path exists for us.
#  - Treated as open-but-not-attackable through this harness.
