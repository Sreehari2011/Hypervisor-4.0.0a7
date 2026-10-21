import socket, ssl, json, datetime, sys

target = "10.10.0.5"
results = {"target": target, "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(), "ports": {}}

def probe(port, use_tls=False):
    info = {"open": False}
    try:
        s = socket.create_connection((target, port), timeout=8)
        info["open"] = True
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(s, server_hostname=target)
            cert = ss.getpeercert(binary_form=True)
            info["tls_version"] = ss.version()
            info["cipher"] = ss.cipher()
            try:
                peercert = ss.getpeercert()
                info["cert"] = peercert
            except Exception as e:
                info["cert_err"] = repr(e)
            ss.sendall(b"GET / HTTP/1.1\r\nHost: 10.10.0.5\r\nUser-Agent: aegis-pilot/1.0\r\nConnection: close\r\n\r\n")
            data = b""
            while True:
                try:
                    chunk = ss.recv(4096)
                except Exception:
                    break
                if not chunk: break
                data += chunk
                if len(data) > 65536: break
            info["http_raw"] = data.decode("latin-1", "replace")
            ss.close()
        else:
            s.settimeout(6)
            if port == 80:
                s.sendall(b"GET / HTTP/1.1\r\nHost: 10.10.0.5\r\nUser-Agent: aegis-pilot/1.0\r\nConnection: close\r\n\r\n")
            data = b""
            while True:
                try:
                    chunk = s.recv(4096)
                except Exception:
                    break
                if not chunk: break
                data += chunk
                if len(data) > 65536: break
            info["banner_raw"] = data.decode("latin-1", "replace")
            s.close()
    except Exception as e:
        info["error"] = repr(e)
    return info

for p in (22, 80, 443):
    results["ports"][str(p)] = probe(p, use_tls=(p == 443))

with open("evidence/port_probe.json", "w") as f:
    json.dump(results, f, indent=2, default=str)

for p, d in results["ports"].items():
    print(f"=== PORT {p} open={d.get('open')} ===")
    if d.get("tls_version"):
        print("TLS:", d["tls_version"], d.get("cipher"))
        print("CERT:", json.dumps(d.get("cert"), default=str)[:600])
    raw = d.get("http_raw") or d.get("banner_raw") or ""
    print(raw[:1500])
    print()
