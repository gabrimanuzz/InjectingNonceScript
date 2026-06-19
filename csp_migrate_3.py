"""
csp_migrate.py  v4
==================
Automatically migrates HTML/JSP/PHP/FTL files to a CSP policy with a nonce:
  1. Adds nonce="${cspNonce}" to every <script> tag that doesn't have it.
  2. Converts inline on* attributes -> data-on* (handled via JS named-function mapping).
  3. Injects a "dispatcher" script that reads data-on* and calls predefined functions.
  4. DOES NOT use new Function() / eval -- safe for CSP.
  5. NEW: Produces a csp_risk_report.json listing all anomalies that need manual review.

Anomalies detected (not auto-fixed, only reported):
  - href="javascript:..."
  - Multi-statement handlers  onclick="a(); b();"
  - External scripts/styles without integrity (SRI)
  - <meta http-equiv="refresh">
  - <iframe> without sandbox
  - <form action="javascript:...">
  - Inline <svg><script>
  - <object> / <embed> / <applet>
  - style="... expression(...)"  (IE legacy)
  - Empty on* handlers  onclick=""
  - Handlers using 'this'
  - Multi-statement handlers auto-converted but flagged

WARNINGS
--------
- Automatically creates a backup (.bak) before modifying any file.
- ALWAYS test on a copy of the project first.
"""

import os
import re
import shutil
import json
import datetime
from typing import List, Tuple, Dict, Optional

# ── Configuration ─────────────────────────────────────────────────────────────

PROJECT_DIR: str = "C:/Users/gmanuzzato/Desktop/EV_FINAL_2/evaluation"
VALID_EXTENSIONS: Tuple[str, ...] = (".html", ".jsp", ".php", ".ftl", ".tmpl")

ENABLE_BACKUP: bool = False
DRY_RUN: bool = False

# Path where the risk report will be written
REPORT_PATH: str = "./csp_risk_report_final.json"

# ── Dispatcher Script ─────────────────────────────────────────────────────────

SCRIPT_DISPATCHER: str = """\
if (!window.__cspDispatcherLoaded) {
    window.__cspDispatcherLoaded = true;

    (function () {
        function findClosest(el, selector) {
            if (!el) return null;
            if (typeof el.closest === 'function') {
                try { return el.closest(selector); } catch (err) { /* fall through */ }
            }
            var node = el;
            while (node && node.nodeType === 1) {
                if (typeof node.matches === 'function') {
                    if (node.matches(selector)) return node;
                } else if (typeof node.getAttribute === 'function') {
                    var attrName = selector.replace(/^\\[|\\]$/g, '');
                    if (node.getAttribute(attrName) !== null) return node;
                }
                node = node.parentNode;
            }
            return null;
        }

        var EVENTS = [
            'click', 'blur', 'focus', 'change', 'submit',
            'mouseover', 'mouseout', 'keydown', 'keyup', 'input'
        ];
        EVENTS.forEach(function (type) {
            document.addEventListener(type, function (e) {
                var attr = 'data-on' + type;
                var rawTarget = e && e.target;
                if (!rawTarget) return;
                var target = findClosest(rawTarget, '[' + attr + ']');
                if (!target) return;

                var value = target.getAttribute(attr);
                if (!value) return;

                var match = value.match(/^(\\w+)(?:\\(([^)]*)\\))?$/);
                if (!match) return;

                var funcName = match[1];
                var func = window[funcName];
                if (typeof func !== 'function') {
                    console.warn('[CSP dispatcher] function not found:', funcName);
                    return;
                }

                var args = match[2]
                    ? match[2].split(',').map(function (a) {
                          a = a.trim().replace(/^['"]|['"]$/g, '');
                          return isNaN(a) ? a : Number(a);
                      })
                    : [e];

                func.apply(target, args);
            }, true);
        });
    })();
}"""

# ── Nonce placeholders per extension ─────────────────────────────────────────

NONCE_PLACEHOLDERS: Dict[str, str] = {
    ".jsp":  "${cspNonce}",
    ".ftl":  "${cspNonce}",
    ".php":  "<?= $cspNonce ?>",
    ".html": "${cspNonce}",
    ".tmpl": "${cspNonce}",
}

# ── Regex: <script> without nonce ─────────────────────────────────────────────

RE_SCRIPT_TAG = re.compile(
    r'<script(?![^>]*\bnonce\b)([^>]*)>',
    re.IGNORECASE
)

# ── Risk detector patterns ────────────────────────────────────────────────────

# Each entry: (risk_id, severity, description, compiled_pattern)
# The pattern is searched line by line; group(0) is the matched snippet.

RISK_PATTERNS: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "HREF_JAVASCRIPT",
        "HIGH",
        "href=\"javascript:...\" executes code inline, blocked by CSP",
        re.compile(r'href\s*=\s*["\']javascript:', re.IGNORECASE),
    ),
    (
        "MULTI_STATEMENT_HANDLER",
        "MEDIUM",
        "Inline handler with multiple statements — dispatcher handles only single calls",
        re.compile(r'\bon\w+\s*=\s*["\'][^"\']*;[^"\']+["\']', re.IGNORECASE),
    ),
    (
        "EXTERNAL_SCRIPT_NO_INTEGRITY",
        "HIGH",
        "External <script src> without integrity attribute (missing SRI)",
        re.compile(r'<script\b(?![^>]*\bintegrity\b)[^>]*\bsrc\s*=\s*["\']https?://', re.IGNORECASE),
    ),
    (
        "EXTERNAL_STYLE_NO_INTEGRITY",
        "MEDIUM",
        "<link rel=stylesheet> pointing to external CDN without integrity (missing SRI)",
        re.compile(r'<link\b(?![^>]*\bintegrity\b)[^>]*\brel\s*=\s*["\']stylesheet["\'][^>]*href\s*=\s*["\']https?://', re.IGNORECASE),
    ),
    (
        "META_REFRESH",
        "MEDIUM",
        "<meta http-equiv=refresh> can be abused for open redirect",
        re.compile(r'<meta\b[^>]*http-equiv\s*=\s*["\']refresh["\']', re.IGNORECASE),
    ),
    (
        "IFRAME_NO_SANDBOX",
        "HIGH",
        "<iframe> without sandbox attribute — can execute scripts in embedded page",
        re.compile(r'<iframe\b(?![^>]*\bsandbox\b)[^>]*>', re.IGNORECASE),
    ),
    (
        "FORM_ACTION_JAVASCRIPT",
        "HIGH",
        "form action=\"javascript:...\" executes code inline",
        re.compile(r'<form\b[^>]*\baction\s*=\s*["\']javascript:', re.IGNORECASE),
    ),
    (
        "SVG_INLINE_SCRIPT",
        "HIGH",
        "Inline <script> inside <svg> — not covered by nonce injection",
        re.compile(r'<svg\b[^>]*>.*?<script\b', re.IGNORECASE | re.DOTALL),
    ),
    (
        "OBJECT_EMBED_APPLET",
        "HIGH",
        "<object>/<embed>/<applet> loads external executable content",
        re.compile(r'<(object|embed|applet)\b', re.IGNORECASE),
    ),
    (
        "STYLE_EXPRESSION",
        "HIGH",
        "IE-legacy style=\"expression(...)\" — executes JS inside CSS",
        re.compile(r'style\s*=\s*["\'][^"\']*\bexpression\s*\(', re.IGNORECASE),
    ),
    (
        "EMPTY_EVENT_HANDLER",
        "LOW",
        "Empty on* handler (onclick=\"\") — probably dead code, safe to remove",
        re.compile(r'\bon\w+\s*=\s*(?:""|\'\')'),
    ),
    (
        "HANDLER_USES_THIS",
        "MEDIUM",
        "Inline handler uses 'this' — verify behavior after migration to data-on*",
        re.compile(r'\bon\w+\s*=\s*["\'][^"\']*\bthis\b', re.IGNORECASE),
    ),
]


# ── Risk data model ───────────────────────────────────────────────────────────

class RiskEntry:
    def __init__(self, file_path: str, line_no: int, risk_id: str,
                 severity: str, description: str, snippet: str):
        self.file_path = file_path
        self.line_no = line_no
        self.risk_id = risk_id
        self.severity = severity
        self.description = description
        self.snippet = snippet[:120]  # truncate long snippets

    def to_dict(self) -> dict:
        return {
            "file": self.file_path,
            "line": self.line_no,
            "risk_id": self.risk_id,
            "severity": self.severity,
            "description": self.description,
            "snippet": self.snippet,
        }


# ── Risk scanner ──────────────────────────────────────────────────────────────

def scan_for_risks(file_path: str, content: str) -> List[RiskEntry]:
    """
    Scans *content* for all known CSP risk patterns.
    Returns a list of RiskEntry objects (one per match).
    """
    entries: List[RiskEntry] = []
    lines = content.splitlines()

    for risk_id, severity, description, pattern in RISK_PATTERNS:
        # For multiline patterns (SVG_INLINE_SCRIPT) search the whole content
        if pattern.flags & re.DOTALL:
            for m in pattern.finditer(content):
                # Find approximate line number
                line_no = content[:m.start()].count('\n') + 1
                entries.append(RiskEntry(
                    file_path, line_no, risk_id, severity, description,
                    m.group(0).replace('\n', ' ')
                ))
        else:
            for line_no, line in enumerate(lines, start=1):
                for m in pattern.finditer(line):
                    entries.append(RiskEntry(
                        file_path, line_no, risk_id, severity, description,
                        m.group(0)
                    ))

    # Deduplicate (same file+line+risk_id)
    seen = set()
    unique: List[RiskEntry] = []
    for e in entries:
        key = (e.file_path, e.line_no, e.risk_id)
        if key not in seen:
            seen.add(key)
            unique.append(e)

    return unique


# ── JSP/FTL-aware inline event converter ─────────────────────────────────────

def _split_html_tokens(text: str) -> List[Tuple[str, bool]]:
    """
    Splits *text* into (chunk, is_open_tag) pairs.
    is_open_tag=True  -> the chunk is an HTML opening tag  <foo ...>
    is_open_tag=False -> everything else
    """
    tokens: List[Tuple[str, bool]] = []
    i = 0
    n = len(text)

    while i < n:
        if text[i] != '<':
            j = text.find('<', i)
            if j == -1:
                tokens.append((text[i:], False))
                break
            tokens.append((text[i:j], False))
            i = j
            continue

        if i + 1 < n and text[i + 1].isalpha():
            j = i + 1
            depth_brace = 0
            depth_jsp = 0
            in_quote: Optional[str] = None

            while j < n:
                c = text[j]

                if in_quote:
                    if c == in_quote:
                        in_quote = None
                    j += 1
                    continue

                if c in ('"', "'"):
                    in_quote = c
                    j += 1
                    continue

                if c in ('$', '#') and j + 1 < n and text[j + 1] == '{':
                    depth_brace += 1
                    j += 2
                    continue

                if c == '{':
                    depth_brace += 1
                    j += 1
                    continue

                if c == '}':
                    if depth_brace > 0:
                        depth_brace -= 1
                    j += 1
                    continue

                if c == '<' and j + 1 < n:
                    rest = text[j + 1:]
                    m_close = re.match(r'/[a-z][\w]*:[a-z][\w]*\s*>', rest, re.IGNORECASE)
                    if m_close:
                        depth_jsp = max(depth_jsp - 1, 0)
                        j += 1 + m_close.end()
                        continue
                    m_open = re.match(r'[a-z][\w]*:[a-z][\w]*', rest, re.IGNORECASE)
                    if m_open:
                        k = j + 1 + m_open.end()
                        in_q2: Optional[str] = None
                        while k < n:
                            ch = text[k]
                            if in_q2:
                                if ch == in_q2:
                                    in_q2 = None
                            elif ch in ('"', "'"):
                                in_q2 = ch
                            elif ch == '>':
                                k += 1
                                if text[k - 2] != '/':
                                    depth_jsp += 1
                                break
                            k += 1
                        j = k
                        continue

                if c == '>' and depth_brace == 0 and depth_jsp == 0:
                    j += 1
                    break

                j += 1

            tokens.append((text[i:j], True))
            i = j
        else:
            j = text.find('>', i)
            if j == -1:
                tokens.append((text[i:], False))
                break
            tokens.append((text[i:j + 1], False))
            i = j + 1

    return tokens


_RE_EVENT_IN_TAG = re.compile(
    r'(?<!-)(?<!\w)\b(on[a-z]+)\s*=\s*(")(.*?)"\s*',
    re.IGNORECASE | re.DOTALL
)
_RE_EVENT_IN_TAG_SQ = re.compile(
    r"(?<!-)(?<!\w)\b(on[a-z]+)\s*=\s*(')(.*?)'\s*",
    re.IGNORECASE | re.DOTALL
)


def _clean_event_value(value: str) -> str:
    value = value.strip()
    value = re.sub(r'^javascript:\s*', '', value, flags=re.IGNORECASE)
    value = re.sub(r'^return\s+', '', value)
    value = value.rstrip(';').strip()
    return value


# ── href="javascript:..." converter ──────────────────────────────────────────
#
# Three cases handled automatically:
#   A) href="javascript:void(0)"  + onclick already present
#      → replace href with "#", leave onclick alone (will be converted by convert_inline_events)
#   B) href="javascript:funcName(args)"  single call, no 'this', no multi-statement
#      → replace href="#" and add data-onclick="funcName(args)"
#   C) complex cases (multi-statement, 'this', expressions)
#      → leave untouched, already flagged in risk report

# Matches an <a> tag fully (JSP-aware tokenizer already isolated it)
_RE_HREF_JS = re.compile(
    r'\bhref\s*=\s*(["\'])javascript:([^"\']*)\1',
    re.IGNORECASE
)

def convert_href_javascript(content: str) -> Tuple[str, List[str]]:
    """
    Converts href="javascript:..." patterns inside <a> tags.
    Returns (modified_content, info_messages).
    """
    messages: List[str] = []
    tokens = _split_html_tokens(content)
    out_parts: List[str] = []

    for chunk, is_open_tag in tokens:
        if not is_open_tag:
            out_parts.append(chunk)
            continue

        # Only process <a ...> tags
        if not re.match(r'<a\b', chunk, re.IGNORECASE):
            out_parts.append(chunk)
            continue

        def replace_href(match: re.Match) -> str:
            js_value: str = match.group(2).strip()

            # Case A: void(0) — just neutralise the href, onclick stays
            if re.match(r'void\s*\(\s*0\s*\)', js_value, re.IGNORECASE) or js_value == '':
                messages.append(f'  ✔ href="javascript:void(0)" → href="#"')
                return 'href="#"'

            # Clean the value exactly like event handlers
            js_value = _clean_event_value(js_value)

            # Reject complex cases
            is_complex = (
                'this' in js_value
                or re.search(r';\s*\w', js_value)          # multi-statement
                or re.search(r'\(.*\(', js_value)           # nested calls
            )
            if is_complex:
                messages.append(
                    f'  ⚠ href="javascript:{js_value}" is complex — left untouched, fix manually'
                )
                return match.group(0)  # leave as-is

            # Simple single call: href="#" + data-onclick
            messages.append(f'  ✔ href="javascript:{js_value}" → href="#" data-onclick="{js_value}"')
            return f'href="#" data-onclick="{js_value}"'

        new_chunk = _RE_HREF_JS.sub(replace_href, chunk)
        out_parts.append(new_chunk)

    return ''.join(out_parts), messages



def convert_inline_events(content: str) -> Tuple[str, List[str]]:
    warnings: List[str] = []
    tokens = _split_html_tokens(content)
    out_parts: List[str] = []

    for chunk, is_open_tag in tokens:
        if not is_open_tag:
            out_parts.append(chunk)
            continue

        def replace_event(match: re.Match) -> str:
            event_name: str = match.group(1).lower()
            value: str = _clean_event_value(match.group(3))

            if not value:
                warnings.append(f"  ⚠ '{event_name}' has empty value — skipped")
                return match.group(0)  # leave as-is

            if 'this' in value:
                warnings.append(
                    f"  ⚠ '{event_name}=\"{value}\"' uses 'this' — "
                    f"in the dispatcher 'this' refers to the target element, verify behavior"
                )
            if re.search(r';\s*\w', value):
                warnings.append(
                    f"  ⚠ '{event_name}=\"{value}\"' has multiple statements — "
                    f"dispatcher handles only the first call, manual refactoring needed"
                )
            if '(' in value and re.search(r'\(.*\(', value):
                warnings.append(
                    f"  ⚠ '{event_name}=\"{value}\"' has nested calls — "
                    f"might require manual refactoring"
                )

            return f'data-{event_name}="{value}" '

        new_chunk = _RE_EVENT_IN_TAG.sub(replace_event, chunk)
        new_chunk = _RE_EVENT_IN_TAG_SQ.sub(replace_event, new_chunk)
        out_parts.append(new_chunk)

    return ''.join(out_parts), warnings


# ── Per-file helpers ──────────────────────────────────────────────────────────

def get_nonce_placeholder(file_path: str) -> str:
    ext: str = os.path.splitext(file_path)[1].lower()
    return NONCE_PLACEHOLDERS.get(ext, "${cspNonce}")


def inject_nonce_to_script_tags(content: str, nonce: str) -> Tuple[str, int]:
    count = 0

    def replace(match: re.Match) -> str:
        nonlocal count
        count += 1
        return f'<script nonce="{nonce}"{match.group(1)}>'

    return RE_SCRIPT_TAG.sub(replace, content), count


def process_file(file_path: str, all_risks: List[RiskEntry]) -> bool:
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        original_content: str = f.read()

    nonce = get_nonce_placeholder(file_path)
    content = original_content

    # 1. Nonce injection
    content, script_count = inject_nonce_to_script_tags(content, nonce)

    # 2. href="javascript:..." conversion
    content, href_messages = convert_href_javascript(content)

    # 3. Inline event conversion (JSP/FTL-aware)
    content, warnings = convert_inline_events(content)
    warnings = href_messages + warnings

    # 4. Scan for risks AFTER modifying — report only what's left unfixed
    risks = scan_for_risks(file_path, content)
    all_risks.extend(risks)

    # Did any events actually change?
    has_events: bool = content != inject_nonce_to_script_tags(original_content, nonce)[0]

    # 5. Inject dispatcher if needed
    if has_events:
        if '</body>' in content:
            content = content.replace('</body>', SCRIPT_DISPATCHER + '\n</body>', 1)
        else:
            content += '\n' + SCRIPT_DISPATCHER

    if content == original_content:
        return False

    if DRY_RUN:
        print(f"  [dry-run] would modify: {file_path}")
        for w in warnings:
            print(w)
        return True

    if ENABLE_BACKUP:
        shutil.copy2(file_path, file_path + '.bak')

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    href_fixed = sum(1 for m in href_messages if m.strip().startswith('✔'))
    changes: List[str] = []
    if script_count > 0:
        changes.append(f"{script_count} script{'s' if script_count > 1 else ''} with nonce")
    if href_fixed > 0:
        changes.append(f"{href_fixed} href javascript fixed")
    if has_events:
        changes.append("inline events -> data-on*")

    risk_count = len(risks)
    if risk_count > 0:
        changes.append(f"{risk_count} risk{'s' if risk_count > 1 else ''} flagged")

    print(f"  ✔ {file_path}  [{', '.join(changes)}]")
    for w in warnings:
        print(w)

    return True


# ── Report writer ─────────────────────────────────────────────────────────────

def write_report(all_risks: List[RiskEntry], total: int, modified: int) -> None:
    if not all_risks:
        print("\n  ✅ No CSP risks found.")
        return

    # Group by severity
    by_severity: Dict[str, List[dict]] = {"HIGH": [], "MEDIUM": [], "LOW": []}
    for r in all_risks:
        by_severity.setdefault(r.severity, []).append(r.to_dict())

    report = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "project_dir": os.path.abspath(PROJECT_DIR),
        "files_scanned": total,
        "files_modified": modified,
        "total_risks": len(all_risks),
        "summary": {sev: len(items) for sev, items in by_severity.items()},
        "risks": by_severity,
    }

    with open(REPORT_PATH, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n  📋 Risk report: {os.path.abspath(REPORT_PATH)}")
    print(f"     HIGH: {report['summary'].get('HIGH', 0)}  "
          f"MEDIUM: {report['summary'].get('MEDIUM', 0)}  "
          f"LOW: {report['summary'].get('LOW', 0)}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run_migration() -> None:
    total_count = 0
    modified_count = 0
    all_risks: List[RiskEntry] = []

    for root, dirs, files in os.walk(PROJECT_DIR):
        dirs[:] = [d for d in dirs if d not in
                   {'.git', 'node_modules', '__pycache__', 'target', 'build'}]

        for file in files:
            if not file.endswith(VALID_EXTENSIONS):
                continue
            total_count += 1
            file_path = os.path.join(root, file)
            try:
                if process_file(file_path, all_risks):
                    modified_count += 1
            except Exception as error:
                print(f"  ❌ Error on {file_path}: {error}")

    print(f"\n{'[DRY-RUN] ' if DRY_RUN else ''}Done: {modified_count}/{total_count} files modified.")
    if ENABLE_BACKUP and not DRY_RUN:
        print("    .bak backups created next to each modified file.")

    write_report(all_risks, total_count, modified_count)


if __name__ == "__main__":
    print(f"CSP migrator v4 — project: {os.path.abspath(PROJECT_DIR)}")
    print(f"Dry-run: {DRY_RUN}  |  Backup: {ENABLE_BACKUP}\n")
    run_migration()
