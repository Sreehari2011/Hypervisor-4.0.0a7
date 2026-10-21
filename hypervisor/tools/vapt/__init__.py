"""hypervisor.tools.vapt — the VAPT toolset (P3, REFACTOR-05 P3 part).

Port card: REFACTOR-05. The families land as scoped, journaled,
duration-bounded, output-capped primitives on the Skeleton 9-2 plane:

  recon    network_scan_nmap (N5 arg sanitization, scope gate,
           structured parse + raw fallback), check_port_listener,
           passive_scan (the oracle's pattern battery as an explicit
           tool), generate_oob_payload / poll_oob_interactions
  web      advanced_http_request, retrieve_url_content, detect_waf,
           headless_dom_navigate/interact (static-DOM engine — a JS
           renderer is an operator-side attachment), web_search_osint
           (operator endpoint), map_vhost
  exec     execute_code / execute_exploit_script (bounded subprocess
           harness, persistence battery, command-target scope gate)
  report   compile_report (evidence-chained, every claim carries its
           EKD id)
  misc     sequential_thinking, analyze_entropy, crypto_analyzer
           (stdlib-truthful subset), list_buffers, analyze_apk /
           analyze_ipa (zipfile static analysis, workspace-resolved
           paths)

Deferred with rationale (landed in P4): frida_hook /
mitm_intercept / ssh_interactive_exec needed devices, daemons or
interactive transports — they are the operator-attached runtimes in
vapt/operator.py (P4, REFACTOR-05 final disposition).
Tool names for everything else are pinned by the Tier-A extractor
routing (memory/extractors.py) so extraction parity holds unchanged.
"""
from __future__ import annotations

import os
from typing import List, Optional

from ..base import Tool


def build_vapt_tools(include_operator: bool = True) -> List[Tool]:
    """The VAPT toolset in registry order. AEGIS_VAPT_TOOLS=0 disables
    the family entirely (a recon-only or analysis-only engagement can
    trim the surface at boot)."""
    from .exec import ExecuteCodeTool, ExecuteExploitTool
    from .misc import (AnalyzeApkTool, AnalyzeIpaTool, CryptoTool,
                       EntropyTool, ListBuffersTool,
                       SequentialThinkingTool)
    from .recon import (NetworkScanTool, OobPayloadTool, OobPollTool,
                        PassiveScanTool, PortListenerTool)
    from .report import CompileReportTool
    from .web import (DetectWafTool, FetchUrlTool, HeadlessDomInteractTool,
                      HeadlessDomNavigateTool, HttpRequestTool,
                      MapVhostTool, WebSearchOsintTool)
    tools = [
        NetworkScanTool(),
        PortListenerTool(),
        PassiveScanTool(),
        OobPayloadTool(),
        OobPollTool(),
        HttpRequestTool(),
        FetchUrlTool(),
        DetectWafTool(),
        HeadlessDomNavigateTool(),
        HeadlessDomInteractTool(),
        WebSearchOsintTool(),
        MapVhostTool(),
        ExecuteCodeTool(),
        ExecuteExploitTool(),
        CompileReportTool(),
        SequentialThinkingTool(),
        EntropyTool(),
        CryptoTool(),
        ListBuffersTool(),
        AnalyzeApkTool(),
        AnalyzeIpaTool(),
    ]
    if include_operator and operator_enabled():
        from .operator import OPERATOR_TOOLS
        tools.extend(t() for t in OPERATOR_TOOLS)
    return tools


def operator_enabled() -> bool:
    """AEGIS_OPERATOR_TOOLS=0 trims the operator-attachment family at
    boot (engagements without mobile/ssh work keep the surface lean).
    Availability of each runtime is STILL probed per-call — this switch
    only controls whether the tools are offered to the model at all."""
    return os.environ.get("AEGIS_OPERATOR_TOOLS", "1").strip().lower() \
        not in ("0", "false", "no", "off")


def vapt_enabled() -> bool:
    return os.environ.get("AEGIS_VAPT_TOOLS", "1").strip().lower() \
        not in ("0", "false", "no", "off")
