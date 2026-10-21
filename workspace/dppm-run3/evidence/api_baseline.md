# /api/ baseline (run3 delta vs prior run)
# Target: https://dppmsserchhip.mizoram.gov.in/api/  (in-scope)
#
# Prior run (per brief):  /api/ returned 308
# This run, GET https://dppmsserchhip.mizoram.gov.in/api/:
#   HTTP 404 with an __next_error__ HTML shell BUT self.__next_f payload contains:
#     "c":["", "api"], ...  ["slug","api","d",null], {"children":["__PAGE__",{}]}
#   => Next.js App Router catch-all/dynamic segment attempted to render '/api'
#      (RSC/Flight stream present), NOT an HTTP-layer 308 redirect.
#   Server: nginx/1.28.3 ; X-Powered-By: Next.js
#
# Takeaway: /api/ is routed by the frontend as a dynamic slug; kept as an
# observation for tracking app changes between runs.
