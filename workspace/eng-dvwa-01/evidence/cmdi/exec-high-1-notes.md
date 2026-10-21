Module: exec — security level HIGH
Filter blocks: ;, &&, ||, "| " (pipe+space), backtick, $(, newline %0a, ||
Bypass: pipe WITHOUT trailing space: ip=localhost|id -> uid=33(www-data).
Filter likely str_replace on exact tokens incl '| ' variant only.
