# React Server Components (RSC/Flight) confirmation evidence
# Target: https://dppmsserchhip.mizoram.gov.in/  (scope sha256:6e91b10c1ea3104f@v1)
# Date: 2026-10-15 ~05:53 UTC
#
# Request: GET / with header "RSC: 1"
# Response:
#   HTTP 200
#   Content-Type: text/x-component            <-- RSC/Flight wire format
#   Server: nginx/1.28.3
#   X-Powered-By: Next.js                     (present on normal HTML responses)
#   Body starts:
#     1:"$Sreact.fragment"
#     2:I[22016,["/_next/static/chunks/0cb1m.rfi373l.js", ...],""]
#     3:I[5500,[...],"Image"] ...
#     0:{"f":[[["",{"children":["__PAGE__",{}] ...  (Flight model rows)
#
# Meaning:
#   The public site is a Next.js App Router app with React Server Components enabled,
#   which is exactly the component class affected by CVE-2025-55182 (React Server Components
#   unsafe deserialization) and CVE-2025-66478 (Next.js wrapper). Framework bundle reports
#   React "19.3.0-canary-3f0b9e61-20260317" (build dated 2026-03-17, i.e. post-Dec-2025 patch),
#   so the RCE is *assumed patched* pending PoC; exposure class for verification is the
#   RSC/Flight deserialization surface itself.
#
# Second surface observed: /_next/image?url=...&w=1080&q=75 returns HTTP 200 image/png with
#   X-Nextjs-Cache: STALE and Content-Disposition: attachment
#   (Next.js image optimizer reachable; historically CVE-2025-XXXXX cache/SSRF class candidates,
#    here url= is relative-only and no remoteUrl fetch was attempted -> no exposure claimed).
