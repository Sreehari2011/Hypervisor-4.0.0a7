Module: exec — security level MEDIUM
Filter blocks: ";" and "&&". Bypass: pipe "|" separator (also "|;", but filter removes "&&" only).
Payload: ip=localhost | id  -> uid=33(www-data) confirmed.
