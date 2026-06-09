"""
csp_migrate.py
==============
Automatically migrates HTML/JSP/PHP/FTL files to a CSP policy with a nonce:
  1. Adds nonce="${cspNonce}" to every <script> tag that doesn't have it.
  2. Converts inline on* attributes → data-on* (handled via JS named-function mapping).
  3. Injects a "dispatcher" script that reads data-on* and calls predefined functions.
  4. DOES NOT use new Function() / eval — safe for CSP.

WARNINGS
--------
- Automatically creates a backup (.bak) before modifying any file.
- Uses regex instead of BeautifulSoup for JSP/FTL to avoid template corruption.
- ALWAYS test on a copy of the project first.
"""

import os
import re
import shutil
from typing import List, Tuple, Dict, re as re_type

# ── Configuration ─────────────────────────────────────────────────────────────

PROJECT_DIR: str = "./evaluation"
VALID_EXTENSIONS: Tuple[str, ...] = (".html", ".jsp", ".php", ".ftl", ".tmpl")

# If True → writes a .bak file next to each modified file
ENABLE_BACKUP: bool = True

# If True → does not write any file, only shows what would be done
DRY_RUN: bool = False

# ── Dispatcher Script (No eval / new Function) ────────────────────────────────
SCRIPT_DISPATCHER: str = """\
<script nonce="${cspNonce}">
(function () {
    var EVENTS = [
        'click', 'blur', 'focus', 'change', 'submit',
        'mouseover', 'mouseout', 'keydown', 'keyup', 'input'
    ];
    EVENTS.forEach(function (type) {
        document.addEventListener(type, function (e) {
            var attr = 'data-on' + type;
            var target = e.target && e.target.closest('[' + attr + ']');
            if (!target) return;

            var value = target.getAttribute(attr); // e.g.: "openModal" or "save(42)"
            if (!value) return;

            // Extract function name and any literal arguments (strings/numbers)
            var match = value.match(/^(\\w+)(?:\\(([^)]*)\\))?$/);
            if (!match) return;

            var funcName = match[1];
            var func = window[funcName];
            if (typeof func !== 'function') {
                console.warn('[CSP dispatcher] function not found:', funcName);
                return;
            }

            // Arguments: split on comma, trim, convert to numeric if possible
            var args = match[2]
                ? match[2].split(',').map(function (a) {
                      a = a.trim().replace(/^['"]|['"]$/g, '');
                      return isNaN(a) ? a : Number(a);
                  })
                : [e]; // no arguments → pass the event

            func.apply(target, args);
        }, true); // capture=true to intercept on elements without bubbling
    });
})();
</script>"""

# ── Regex Patterns ────────────────────────────────────────────────────────────

RE_SCRIPT_TAG: re_type.Pattern = re.compile(
    r'<script(?![^>]*\bnonce\b)([^>]*)>',
    re.IGNORECASE
)

RE_INLINE_EVENT: re_type.Pattern = re.compile(
    r'\b(on[a-z]+)\s*=\s*(["\'])(.*?)\2',
    re.IGNORECASE | re.DOTALL
)

NONCE_PLACEHOLDERS: Dict[str, str] = {
    ".jsp": '${cspNonce}',
    ".ftl": '${cspNonce}',
    ".php": '<?= $cspNonce ?>',
    ".html": '${cspNonce}',
    ".tmpl": '${cspNonce}',
}


# ── Functions ─────────────────────────────────────────────────────────────────

def get_nonce_placeholder(file_path: str) -> str:
    """
    Returns the appropriate nonce placeholder based on the file extension.
    """
    ext: str = os.path.splitext(file_path)[1].lower()
    return NONCE_PLACEHOLDERS.get(ext, '${cspNonce}')


def inject_nonce_to_script_tags(content: str, nonce: str) -> Tuple[str, int]:
    """
    Adds the nonce attribute to every <script> tag that does not already have one.
    """
    count: int = 0

    def replace(match: re_type.Match) -> str:
        nonlocal count
        count += 1
        other_attributes: str = match.group(1)
        return f'<script nonce="{nonce}"{other_attributes}>'

    new_content: str = RE_SCRIPT_TAG.sub(replace, content)
    return new_content, count


def convert_inline_events(content: str) -> Tuple[str, List[str]]:
    """
    Replaces inline event attributes (on*="...") with data-on*="...".
    Returns a tuple with the modified content and a list of refactoring warnings.
    """
    warnings: List[str] = []

    def replace(match: re_type.Match) -> str:
        event_name: str = match.group(1).lower()
        value: str = match.group(3).strip()

        # Clean common inline patterns
        value = re.sub(r'^return\s+', '', value)
        value = value.rstrip(';').strip()

        # Flag complex cases that might fail with the dispatcher
        if 'this' in value:
            warnings.append(
                f"  ⚠ '{event_name}=\"{value}\"' uses 'this' → "
                f"in the dispatcher 'this' refers to the target element, verify behavior"
            )
        if '(' in value and re.search(r'\(.*\(', value):
            warnings.append(
                f"  ⚠ '{event_name}=\"{value}\"' has nested calls → "
                f"might require manual refactoring"
            )

        return f'data-{event_name}="{value}"'

    new_content: str = RE_INLINE_EVENT.sub(replace, content)
    return new_content, warnings


def process_file(file_path: str) -> bool:
    """
    Processes a single file. Injects nonces, converts inline events,
    and appends the dispatcher script if needed. Returns True if modified.
    """
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        original_content: str = f.read()

    nonce: str = get_nonce_placeholder(file_path)
    content: str = original_content

    # 1. Inject nonce into <script> tags
    script_count: int
    content, script_count = inject_nonce_to_script_tags(content, nonce)

    # 2. Convert inline events
    warnings: List[str]
    content, warnings = convert_inline_events(content)

    # Recalculate whether the file actually had inline events modified
    content_post_script: str = RE_SCRIPT_TAG.sub(
        lambda m: f'<script nonce="{nonce}"{m.group(1)}>', original_content
    )
    has_events: bool = convert_inline_events(content_post_script)[0] != content_post_script

    # 3. Inject dispatcher script only if inline events were converted
    if has_events:
        if '</body>' in content:
            content = content.replace('</body>', SCRIPT_DISPATCHER + '\n</body>', 1)
        else:
            content += '\n' + SCRIPT_DISPATCHER

    # Skip if no changes were made
    if content == original_content:
        return False

    if DRY_RUN:
        print(f"  [dry-run] would have modified: {file_path}")
        for warning in warnings:
            print(warning)
        return True

    # Create backup file
    if ENABLE_BACKUP:
        shutil.copy2(file_path, file_path + '.bak')

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    # Print summary report for the file
    changes: List[str] = []
    if script_count > 0:
        changes.append(f"{script_count} scripts with nonce")
    if has_events:
        changes.append("inline events → data-on*")

    print(f"  ✔ {file_path}  [{', '.join(changes)}]")
    for warning in warnings:
        print(warning)

    return True


def run_migration() -> None:
    """
    Walks through the project directory and processes all eligible source files,
    ignoring common non-source folders.
    """
    total_count: int = 0
    modified_count: int = 0

    for root, dirs, files in os.walk(PROJECT_DIR):
        # Skip typical non-source directories dynamically
        dirs[:] = [d for d in dirs if d not in
                   {'.git', 'node_modules', '__pycache__', 'target', 'build'}]

        for file in files:
            if not file.endswith(VALID_EXTENSIONS):
                continue
            total_count += 1
            file_path: str = os.path.join(root, file)
            try:
                if process_file(file_path):
                    modified_count += 1
            except Exception as error:
                print(f"  ❌ Error on {file_path}: {error}")

    print(f"\n{'[DRY-RUN] ' if DRY_RUN else ''}Done: {modified_count}/{total_count} files modified.")
    if ENABLE_BACKUP and not DRY_RUN:
        print("    .bak backups created next to each modified file.")


if __name__ == "__main__":
    print(f"CSP migrator — project: {os.path.abspath(PROJECT_DIR)}")
    print(f"Dry-run: {DRY_RUN}  |  Backup: {ENABLE_BACKUP}\n")
    run_migration()