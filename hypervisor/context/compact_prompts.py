"""hypervisor.context.compact_prompts — PORT-01 (P2) + UX-02 (a7).

ORIGIN: the compaction prompt family was carried byte-for-byte from the
3.7.3 oracle (src/core/compact_prompts.py, itself generated from the
byte-faithful golden texts with 13/13 programmatic byte-fidelity checks
against the 2026-03-31 Claude Code leak and the v2.1.88 snapshot).

UX-02 (a7): the three task templates (BASE / FROM / UP_TO) were
re-oriented from coding-session vocabulary to AEGIS engagement
vocabulary — section 3 becomes "Hosts, Services, Endpoints and
Artifacts", the analysis checklist collects hosts/credentials/tool
outputs instead of code snippets, and the closing example instructions
reference engagement focus instead of typescript/test output. The
no-tools preamble names AEGIS tools instead of the upstream CLI's. The
load-bearing structure is preserved exactly: the nine numbered sections,
the <analysis>/<summary> example shape, section 6 (ALL operator
messages) and the section 9 verbatim-quote anti-drift clause, and the
single Additional-Instructions seam. Replay is unaffected: summary_hash
covers each fold's summary TEXT (journaled at fold time, verified
against its sidecar), and replay asserts window_hash/brief_hash only —
prompt_hash is journaled forensics, never re-derived. The sha pins in
tests/test_context_engine.py are the UX-02 cuts and remain the drift
guard for every future fold. The oracle-verbatim originals remain in
the 3.7.3 tree (src/core/compact_prompts.py).

The AEGIS adaptation (engagement emphasis + the binding id-preservation
rule) lives ONLY in the single Additional-Instructions seam assembled
by context/compact.py (get_compact_prompt / get_partial_compact_prompt),
never here.

4.0 deltas (module move only): core/compact_prompts.py ->
context/compact_prompts.py; the file stays import-free pure constants;
no size knobs (any tuning is a parameter at the call site, same
defaults).
"""

# src/services/compact/prompt.ts L19-26 (leak vintage == v2.1.88);
# UX-02: tool list re-pointed at the AEGIS registry names.
NO_TOOLS_PREAMBLE = (
    'CRITICAL: Respond with TEXT ONLY. Do NOT call any tools.\n\n- Do NOT u'
    'se run_command, read_file, write_file, http_probe, or ANY other tool'
    '.\n- You already have all the context you need in the conversation abo'
    've.\n- Tool calls will be REJECTED and will waste your only turn — yo'
    'u will fail the task.\n- Your entire response must be plain text: an '
    '<analysis> block followed by a <summary> block.\n\n'
)

# src/services/compact/prompt.ts L269-272
NO_TOOLS_TRAILER = (
    '\n\nREMINDER: Do NOT call any tools. Respond with plain text only — an <an'
    'alysis> block followed by a <summary> block. Tool calls will be rejected'
    ' and you will fail the task.'
)

# src/services/compact/prompt.ts L61-143 — the nine-section task, full
# compact (DETAILED_ANALYSIS_INSTRUCTION_BASE interpolated). Section 6
# (all operator messages) and section 9 (optional next step with
# verbatim quotes) are the load-bearing anti-drift sections (spec 6.4).
# UX-02: engagement-native section content (see module docstring).
BASE_COMPACT_TEMPLATE = (
    'Your task is to create a detailed summary of the conversation so far, pa'
    "ying close attention to the operator's explicit directives and your pre"
    'vious actions.\nThis summary should be thorough in capturing technical '
    'details, engagement facts, and attack-path decisions that would be essen'
    'tial for continuing the VAPT engagement without losing context.\n\nBefo'
    're providing your final summary, wrap your analysis in <analysis> tags '
    "to organize your thoughts and ensure you've covered all necessary point"
    's. In your analysis process:\n\n1. Chronologically analyze each message '
    "and section of the conversation. For each section thoroughly identify:\n"
    "   - The operator's explicit directives and intents\n   - Your approach"
    ' to addressing them\n   - Key decisions, technical concepts and engagem'
    'ent facts\n   - Specific details like:\n     - hosts, ports and service'
    's\n     - endpoints, parameters and routes\n     - credentials, tokens '
    'and session state\n     - tool commands and their key outputs\n     - a'
    'rtifact, evidence and finding ids\n   - Errors and tool failures that y'
    'ou ran into and how you fixed or worked around them\n   - Pay special a'
    'ttention to specific operator feedback that you received, especially i'
    'f the operator told you to do something differently.\n2. Double-check f'
    'or technical accuracy and completeness, addressing each required eleme'
    'nt thoroughly.\n\nYour summary should include the following sections:'
    '\n\n1. Primary Request and Intent: Capture the operator\'s objective, '
    'scope bounds, rules of engagement and all explicit directives in deta'
    'il\n2. Key Technical Concepts: List the engagement technology stack, t'
    'he attack classes in play, and the tooling constraints.\n3. Hosts, Ser'
    'vices, Endpoints and Artifacts: Enumerate the hosts, services, endpoin'
    'ts, credentials, workspace files and artifacts examined, discovered or'
    ' created. Pay special attention to the most recent messages, include t'
    'he exact tool commands and their key outputs where applicable, and in'
    'clude a summary of why each matters to the engagement.\n4. Errors and f'
    'ixes: List tool failures, errors and gate denials that you ran into, a'
    'nd how you fixed or worked around them. Pay special attention to speci'
    'fic operator feedback that you received, especially if the operator to'
    'ld you to do something differently.\n5. Problem Solving: Document hypot'
    'heses tested, exploit attempt outcomes, and any ongoing investigation '
    'efforts.\n6. All operator messages: List ALL operator messages that ar'
    'e not tool results. These are critical for understanding the operator'
    "'s feedback and changing intent.\n7. Pending Tasks: Outline any pending"
    ' engagement tasks, blocked items and their dependencies.\n8. Current W'
    'ork: Describe in detail precisely what was being worked on immediately'
    ' before this summary request, paying special attention to the most rec'
    'ent messages from both operator and assistant. Include hosts, endpoint'
    's, tool commands and key outputs where applicable.\n9. Optional Next St'
    'ep: List the next step that you will take that is related to the most '
    'recent work you were doing. IMPORTANT: ensure that this step is DIRECT'
    "LY in line with the operator's most recent explicit directives, and th"
    'e task you were working on immediately before this summary request. If'
    ' your last task was concluded, then only list next steps that are exp'
    'licitly in line with the operator\'s request. Do not start on tangenti'
    'al requests or really old requests that were already completed withou'
    't confirming with the operator first.\n                       If there '
    'is a next step, include direct quotes from the most recent conversati'
    'on showing exactly what task you were working on and where you left of'
    'f. This should be verbatim to ensure there\'s no drift in task interpr'
    'etation.\n\nHere\'s an example of how your output should be structured'
    ':\n\n<example>\n<analysis>\n[Your thought process, ensuring all points'
    ' are covered thoroughly and accurately]\n</analysis>\n\n<summary>\n1. '
    'Primary Request and Intent:\n   [Detailed description]\n\n2. Key Techn'
    'ical Concepts:\n   - [Concept 1]\n   - [Concept 2]\n   - [...]\n\n3. H'
    'osts, Services, Endpoints and Artifacts:\n   - [Host / Service 1]\n  '
    '    - [Summary of why this matters to the engagement]\n      - [Key to'
    'ol commands and outputs]\n   - [Endpoint / Artifact 2]\n      - [Key d'
    'etails]\n   - [...]\n\n4. Errors and fixes:\n    - [Detailed descript'
    'ion of error 1]:\n      - [How you fixed the error]\n      - [Operato'
    'r feedback on the error if any]\n    - [...]\n\n5. Problem Solving:\n '
    '  [Description of hypotheses tested, exploit attempts and outcomes]\n'
    '\n6. All operator messages: \n    - [Detailed non tool use operator m'
    'essage]\n    - [...]\n\n7. Pending Tasks:\n    - [Task 1]\n    - [Task'
    ' 2]\n    - [...]\n\n8. Current Work:\n   [Precise description of curr'
    'ent work]\n\n9. Optional Next Step:\n   [Optional Next step to take]'
    '\n\n</summary>\n</example>\n\nPlease provide your summary based on th'
    'e conversation so far, following this structure and ensuring precision'
    ' and thoroughness in your response. \n\nThere may be additional summari'
    'zation instructions provided in the included context. If so, remember'
    'to follow these instructions when creating the above summary. Examples '
    'of instructions include:\n<example>\n## Compact Instructions\nWhen summ'
    'arizing the conversation focus on credential handling and scope bounds '
    'and also remember the tool failures you ran into and how you worked ar'
    'ound them.\n</example>\n\n<example>\n# Summary instructions\nWhen you '
    'are using compact - please focus on exploit attempt outcomes and evide'
    'nce artifacts. Include tool outputs verbatim.\n</example>\n'
)

# src/services/compact/prompt.ts L145-204 — direction 'from': the recent
# tail after retained earlier context (cache-aware, mechanism M4).
# UX-02: engagement-native section content.
PARTIAL_COMPACT_TEMPLATE_FROM = (
    'Your task is to create a detailed summary of the RECENT portion of the c'
    'onversation — the messages that follow earlier retained context. The ear'
    'lier messages are being kept intact and do NOT need to be summarized. Fo'
    'cus your summary on what was discussed, learned, and accomplished in the'
    ' recent messages only.\n\nBefore providing your final summary, wrap your '
    "analysis in <analysis> tags to organize your thoughts and ensure you've "
    'covered all necessary points. In your analysis process:\n\n1. Analyze the'
    ' recent messages chronologically. For each section thoroughly identify:'
    "\n   - The operator's explicit directives and intents\n   - Your approac"
    'h to addressing them\n   - Key decisions, technical concepts and engag'
    'ement facts\n   - Specific details like:\n     - hosts, ports and servi'
    'ces\n     - endpoints, parameters and routes\n     - credentials, toke'
    'ns and session state\n     - tool commands and their key outputs\n    '
    ' - artifact, evidence and finding ids\n   - Errors and tool failures th'
    'at you ran into and how you fixed or worked around them\n   - Pay spec'
    'ial attention to specific operator feedback that you received, especia'
    'lly if the operator told you to do something differently.\n2. Double-ch'
    'eck for technical accuracy and completeness, addressing each required e'
    'lement thoroughly.\n\nYour summary should include the following section'
    's:\n\n1. Primary Request and Intent: Capture the operator\'s objective '
    "and directives from the recent messages\n2. Key Technical Concepts: Li"
    'st the engagement technology stack, attack classes and tooling constra'
    'ints discussed recently.\n3. Hosts, Services, Endpoints and Artifacts: '
    'Enumerate the hosts, services, endpoints, credentials, workspace files '
    'and artifacts examined, discovered or created in the recent portion. I'
    'nclude the exact tool commands and their key outputs where applicable '
    'and include a summary of why each matters to the engagement.\n4. Error'
    's and fixes: List tool failures and errors encountered and how they we'
    're fixed or worked around.\n5. Problem Solving: Document hypotheses te'
    'sted, exploit attempt outcomes and ongoing investigation efforts.\n6.'
    ' All operator messages: List ALL operator messages from the recent por'
    'tion that are not tool results.\n7. Pending Tasks: Outline any pending '
    'engagement tasks from the recent messages.\n8. Current Work: Describe '
    'precisely what was being worked on immediately before this summary req'
    'uest.\n9. Optional Next Step: List the next step related to the most r'
    'ecent work. Include direct quotes from the recent conversation.\n\nHe'
    "re's an example of how your output should be structured:\n\n<example>\n"
    '<analysis>\n[Your thought process, ensuring all points are covered tho'
    'roughly and accurately]\n</analysis>\n\n<summary>\n1. Primary Request '
    'and Intent:\n   [Detailed description]\n\n2. Key Technical Concepts:'
    '\n   - [Concept 1]\n   - [Concept 2]\n\n3. Hosts, Services, Endpoints'
    ' and Artifacts:\n   - [Host / Service 1]\n      - [Summary of why thi'
    's matters to the engagement]\n      - [Key tool commands and outputs]'
    '\n\n4. Errors and fixes:\n    - [Error description]:\n      - [How you'
    ' fixed it]\n\n5. Problem Solving:\n   [Description]\n\n6. All operator'
    ' messages:\n    - [Detailed non tool use operator message]\n\n7. Pendi'
    'ng Tasks:\n    - [Task 1]\n\n8. Current Work:\n   [Precise descriptio'
    'n of current work]\n\n9. Optional Next Step:\n   [Optional Next step t'
    'o take]\n\n</summary>\n</example>\n\nPlease provide your summary based'
    ' on the RECENT messages only (after the retained earlier context), fol'
    'lowing this structure and ensuring precision and thoroughness in your '
    'response.\n'
)

# src/services/compact/prompt.ts L208-267 — direction 'up_to': the
# summarized prefix; section 9 becomes Context for Continuing Work.
# UX-02: engagement-native section content.
PARTIAL_COMPACT_TEMPLATE_UP_TO = (
    'Your task is to create a detailed summary of this conversation. This sum'
    'mary will be placed at the start of a continuing session; newer messages'
    ' that build on this context will follow after your summary (you do not '
    'see them here). Summarize thoroughly so that someone reading only your '
    'summary and then the newer messages can fully understand what happened '
    'and continue the engagement.\n\nBefore providing your final summary, wr'
    "ap your analysis in <analysis> tags to organize your thoughts and ensur"
    "e you've covered all necessary points. In your analysis process:\n\n1. "
    'Chronologically analyze each message and section of the conversation. F'
    "or each section thoroughly identify:\n   - The operator's explicit dire"
    'ctives and intents\n   - Your approach to addressing them\n   - Key dec'
    'isions, technical concepts and engagement facts\n   - Specific details'
    ' like:\n     - hosts, ports and services\n     - endpoints, parameters'
    ' and routes\n     - credentials, tokens and session state\n     - tool'
    ' commands and their key outputs\n     - artifact, evidence and finding'
    ' ids\n   - Errors and tool failures that you ran into and how you fixe'
    'd or worked around them\n   - Pay special attention to specific operat'
    'or feedback that you received, especially if the operator told you to d'
    'o something differently.\n2. Double-check for technical accuracy and co'
    'mpleteness, addressing each required element thoroughly.\n\nYour summar'
    'y should include the following sections:\n\n1. Primary Request and Int'
    "ent: Capture the operator's objective, scope bounds, rules of engageme"
    'nt and all explicit directives in detail\n2. Key Technical Concepts: L'
    'ist the engagement technology stack, the attack classes in play, and t'
    'he tooling constraints.\n3. Hosts, Services, Endpoints and Artifacts: '
    'Enumerate the hosts, services, endpoints, credentials, workspace files'
    ' and artifacts examined, discovered or created. Include the exact tool'
    ' commands and their key outputs where applicable and include a summary'
    ' of why each matters to the engagement.\n4. Errors and fixes: List tool'
    ' failures, errors and gate denials encountered and how they were fixed'
    ' or worked around.\n5. Problem Solving: Document hypotheses tested, ex'
    'ploit attempt outcomes and ongoing investigation efforts.\n6. All oper'
    'ator messages: List ALL operator messages that are not tool results.'
    '\n7. Pending Tasks: Outline any pending engagement tasks.\n8. Work Comp'
    'leted: Describe what was accomplished by the end of this portion.\n9. C'
    'ontext for Continuing Work: Summarize any engagement context, decision'
    's, or state that would be needed to understand and continue the work i'
    'n subsequent messages.\n\nHere\'s an example of how your output should'
    ' be structured:\n\n<example>\n<analysis>\n[Your thought process, ensur'
    'ing all points are covered thoroughly and accurately]\n</analysis>\n\n'
    '<summary>\n1. Primary Request and Intent:\n   [Detailed description]\n'
    '\n2. Key Technical Concepts:\n   - [Concept 1]\n   - [Concept 2]\n\n3.'
    ' Hosts, Services, Endpoints and Artifacts:\n   - [Host / Service 1]\n '
    '     - [Summary of why this matters to the engagement]\n      - [Key t'
    'ool commands and outputs]\n\n4. Errors and fixes:\n    - [Error descr'
    'iption]:\n      - [How you fixed it]\n\n5. Problem Solving:\n   [Descr'
    'iption]\n\n6. All operator messages:\n    - [Detailed non tool use ope'
    'rator message]\n\n7. Pending Tasks:\n    - [Task 1]\n\n8. Work Complet'
    'ed:\n   [Description of what was accomplished]\n\n9. Context for Conti'
    'nuing Work:\n   [Key engagement context, decisions, or state needed to'
    ' continue the work]\n\n</summary>\n</example>\n\nPlease provide your '
    'summary following this structure, ensuring precision and thoroughness '
    'in your response.\n'
)

# src/services/compact/prompt.ts L345-370 — the continuation message
# (Appendix B.3). The bracketed lines in the notes template are
# conditional blocks; the fixed texts below are verbatim except the
# UX-02 transcript-pointer vocabulary (tool outputs, not code snippets).
CONTINUATION_HEADER = (
    'This session is being continued from a previous conversation that ran ou'
    't of context. The summary below covers the earlier portion of the conver'
    'sation.'
)
CONTINUATION_TRANSCRIPT_POINTER = (
    'If you need specific details from before compaction (like exact tool out'
    'puts, error messages, or artifacts you generated), read the full transcri'
    'pt at: {transcriptPath}'
)
CONTINUATION_RECENT_PRESERVED = (
    'Recent messages are preserved verbatim.'
)
CONTINUATION_RESUME_GUARD = (
    'Continue the conversation from where it left off without asking the user'
    ' any further questions. Resume directly — do not acknowledge the summary'
    ', do not recap what was happening, do not preface with "I\'ll continue" o'
    'r similar. Pick up the last task as if the break never happened.'
)
CONTINUATION_AUTONOMOUS_GUARD = (
    'You are running in autonomous/proactive mode. This is NOT a first wake-u'
    'p — you were already working autonomously before compaction. Continue yo'
    'ur work loop: pick up where you left off based on the summary above. Do '
    'not greet the user or ask what to work on.'
)

# The single injection seam (spec 6.3 / annotation 5): engagement focus
# directives enter ONLY here, prefixed exactly as the source assembles
# them. The AEGIS adaptation set (engagement emphasis + id-preservation)
# rides this seam; nothing else may alter the texts.
ADDITIONAL_INSTRUCTIONS_PREFIX = "\n\nAdditional Instructions:\n"
