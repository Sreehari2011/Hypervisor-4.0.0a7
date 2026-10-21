# =============================================================================
# AEGIS Hypervisor 4.0 — containerized engagement runtime
# Image tag: aegis-hypervisor:4.0.0a6
#
# VERIFIED BUILD FINGERPRINT (Test-3 exit criterion: PASS):
#   sha256:d0b8b1b4ce6a07f4974852afb93c9fee6daa2a3182cf6c105defa47c63d71047
# Recorded in image labels (com.aegis.verified-build.sha256), BUILD.sha256,
# and the entrypoint banner.
#
# NOTE ON BASE PINNING: the digest above does NOT resolve as a
# kalilinux/kali-rolling manifest on Docker Hub (registry check 2026-10-12:
# HTTP 404; then-current :latest = sha256:02f5d6c019e549b0...), so it is
# carried as the verified-build fingerprint, NOT pinned in FROM. To
# hard-freeze the base layer once you confirm a pullable RepoDigest:
#     docker images --digests | grep kali-rolling
#     FROM kalilinux/kali-rolling@sha256:<your-verified-RepoDigest>
#
# Core is stdlib-plus-one: the SOLE declared runtime dependency is the
# adapter's httpx transport (pyproject: dependencies = ["httpx>=0.27"],
# imported lazily at call time inside OpenAICompatClient._http — Test-4
# caught it when the clean image died on the first model call).
# Doctor-required runtimes provisioned below:
#   ssh (openssh-client) / sshpass / nmap / mitmdump (mitmproxy) / frida-tools
# =============================================================================

FROM kalilinux/kali-rolling:latest

LABEL org.opencontainers.image.title="AEGIS Hypervisor 4.0 engagement runtime" \
      org.opencontainers.image.version="4.0.0a6" \
      org.opencontainers.image.description="Stdlib-plus-one hypervisor (httpx transport) + VAPT arsenal — exit-criterion test bed" \
      org.opencontainers.image.base.name="kalilinux/kali-rolling" \
      com.aegis.build.note="4.0.0a6: PILOT-03 gate fix (greedy multi-label _DOMAIN_RE + fail-closed targetless-network guard). Test-3 verified-build fingerprint d0b8b1b4 SUPERSEDED — re-verify via in-container scripts/run-tests.sh"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# --- 1. System deps + VAPT arsenal (apt only, no pip) --------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates curl wget git zsh jq libcap2-bin \
    python3 python3-pip \
    iproute2 iputils-ping net-tools dnsutils \
    nmap masscan nikto sqlmap hydra \
    gobuster dirb ffuf whatweb wpscan \
    exploitdb \
    john hashcat wordlists \
    radare2 gdb ltrace strace \
    binwalk foremost \
    tcpdump tshark \
    openssh-client sshpass proxychains4 \
    adb fastboot default-jdk apktool \
    mitmproxy \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# --- 1b. nmap file-cap normalization ---------------------------------------
# Kali ships /usr/lib/nmap/nmap with file caps
# cap_net_bind_service,cap_net_admin,cap_net_raw. This container runs
# cap_drop:ALL + cap_add:NET_RAW,NET_ADMIN — when ANY file capability
# sits outside the process bounding set, execve refuses with EPERM for
# every user (root included; the /usr/bin/nmap sh wrapper surfaces it
# as rc=127 "Operation not permitted" — the PILOT-02 finding).
# Normalize the binary to exactly the two caps the engagement compose
# grants, so it execs and the unprivileged aegis user re-gains raw
# sockets at exec time. The compose NET_BIND_SERVICE cap_add is the
# belt-and-braces path; either alone unblocks nmap.
RUN setcap cap_net_admin,cap_net_raw=eip /usr/lib/nmap/nmap

# --- 2. frida for frida_hook (mobile dynamic instrumentation) ------------------
# Keep the container's frida client version in sync with the frida-server you
# push to targets — mismatched versions are the #1 cause of attach failures.
RUN apt-get update && \
    (apt-get install -y --no-install-recommends frida-tools || \
     pip3 install --break-system-packages frida-tools) && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# --- 2b. Adapter transport — the engine's ONE declared runtime dep ----------
# hypervisor/adapters/openai.py rides httpx (lazy import at call time
# inside OpenAICompatClient._http); pyproject declares it. Test-4's clean
# container caught the undeclared-dependency gap when the first model
# call died inside _http() — the doctor now blocks on this (check:
# 'adapter transport: httpx').
RUN pip3 install --break-system-packages "httpx>=0.27"

# --- 3. Proxychains egress via engagement SOCKS5 relay -------------------------
# CREDENTIALS STRIPPED from this shared kit — restore before building
# (README.md, "Restore credentials"), or mount proxychains4.conf at runtime
# (see docker-compose.yaml) so creds never enter the image layers.
RUN printf '%s\n' \
    "strict_chain" \
    "quiet_mode" \
    "proxy_dns" \
    "remote_dns_subnet 224" \
    "tcp_read_time_out 15000" \
    "tcp_connect_time_out 8000" \
    "localnet 10.0.0.0/255.0.0.0" \
    "localnet 127.0.0.0/255.0.0.0" \
    "[ProxyList]" \
    "socks5 PROXY_HOST PROXY_PORT PROXY_USER PROXY_PASS" \
    > /etc/proxychains4.conf

# --- 4. Operator user + workspace layout ----------------------------------------
RUN useradd -m -s /bin/bash aegis
WORKDIR /app
RUN mkdir -p /app/workspace /app/logs /app/templates /app/history && \
    chown -R aegis:aegis /app

# --- 5. Entrypoint: pre-flight doctor, then hand off to CMD ---------------------
COPY --chown=aegis:aegis docker/entrypoint.sh /usr/local/bin/aegis-entrypoint.sh
RUN chmod 0755 /usr/local/bin/aegis-entrypoint.sh

# --- 6. Hypervisor source (nothing to compile, nothing to install) --------------
COPY --chown=aegis:aegis . /app/
RUN pip3 install --break-system-packages -q "pytest>=8"
ENV PYTEST_ADDOPTS="--basetemp=/app/.pytest-tmp"

# Kali python3 is >= 3.11 (doctor requirement). The symlink keeps every
# `python3.11 ...` command from the workstation workflow working verbatim.
RUN ln -s /usr/bin/python3 /usr/local/bin/python3.11

USER aegis
ENV HOME=/home/aegis
ENV PATH="/home/aegis/.local/bin:${PATH}"

ENTRYPOINT ["/usr/local/bin/aegis-entrypoint.sh"]
CMD ["/bin/zsh"]
