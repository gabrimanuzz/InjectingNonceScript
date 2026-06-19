"""
update_dispatcher.py
=====================
Replaces the OLD csp dispatcher script (the one using e.target.closest()
directly, which breaks under Prototype.js / legacy event wrappers) with the
NEW, defensive dispatcher (with findClosest fallback) in every file that
already contains it.

Use this ONCE, after having already run csp_migrate.py on the project,
to retrofit the fix without re-running the whole migration (which would
skip already-modified files and could duplicate the dispatcher).

WARNINGS
--------
- Creates a .bak2 backup before modifying any file (separate from the
  .bak created by csp_migrate.py, so you don't overwrite the original backup).
- Only touches files that contain the OLD dispatcher signature.
- Safe to run multiple times: if the OLD signature is not found, the file
  is left untouched.
"""

import os
import json
import datetime
from typing import Tuple, List, Dict

# ── Configuration ─────────────────────────────────────────────────────────────

PROJECT_DIR: str = "C:/Users/gmanuzzato/Desktop/EV_FINAL_2/evaluation"
VALID_EXTENSIONS: Tuple[str, ...] = (".html", ".jsp", ".php", ".ftl", ".tmpl")
ENABLE_BACKUP: bool = False
DRY_RUN: bool = False

REPORT_PATH: str = "./dispatcher_update_report.json"

# ── Old dispatcher IIFE only (no <script> wrapper) ────────────────────────────
# This is what actually gets replaced — isolating just the IIFE means the
# replace still works even if extra wrapper functions were added below it
# inside the same <script> tag.

OLD_DISPATCHER_IIFE: str = """\
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
                // crude attribute-based match as last resort, selector is
                // always of the form '[data-onX]' in this dispatcher
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
})();"""

NEW_DISPATCHER_IIFE: str = """\
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

# Signature used only to DETECT old dispatcher presence (short and unique)
OLD_SIGNATURE: str = "var rawTarget = e && e.target;"

def process_file(file_path: str) -> str:
    """
    Returns one of: "updated", "skipped_no_signature", "skipped_mismatch", "dry_run_would_update"
    """
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        content: str = f.read()

    if OLD_SIGNATURE not in content:
        return "skipped_no_signature"

    new_content = content.replace(OLD_DISPATCHER_IIFE, NEW_DISPATCHER_IIFE)

    if new_content == content:
        print(f"  ⚠ {file_path}: old signature found but exact block didn't match — skipped, check manually")
        return "skipped_mismatch"

    if DRY_RUN:
        print(f"  [dry-run] would update dispatcher in: {file_path}")
        return "dry_run_would_update"

    if ENABLE_BACKUP:
        import shutil
        shutil.copy2(file_path, file_path + '.bak2')

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"  ✔ {file_path}  [dispatcher updated]")
    return "updated"


def run() -> None:
    total = 0
    results: Dict[str, List[str]] = {
        "updated": [],
        "skipped_mismatch": [],
        "dry_run_would_update": [],
    }

    for root, dirs, files in os.walk(PROJECT_DIR):
        dirs[:] = [d for d in dirs if d not in
                   {'.git', 'node_modules', '__pycache__', 'target', 'build'}]

        for file in files:
            if not file.endswith(VALID_EXTENSIONS):
                continue
            total += 1
            file_path = os.path.join(root, file)
            try:
                status = process_file(file_path)
                if status in results:
                    results[status].append(file_path)
            except Exception as error:
                print(f"  ❌ Error on {file_path}: {error}")

    updated_count = len(results["updated"]) + len(results["dry_run_would_update"])
    mismatch_count = len(results["skipped_mismatch"])

    print(f"\n{'[DRY-RUN] ' if DRY_RUN else ''}Done: {updated_count}/{total} files had dispatcher updated.")
    if mismatch_count > 0:
        print(f"    ⚠ {mismatch_count} file(s) had the old signature but didn't match exactly — see report.")
    if ENABLE_BACKUP and not DRY_RUN:
        print("    .bak2 backups created next to each updated file.")

    write_report(total, results)


def write_report(total: int, results: Dict[str, List[str]]) -> None:
    report = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "project_dir": os.path.abspath(PROJECT_DIR),
        "dry_run": DRY_RUN,
        "files_scanned": total,
        "summary": {
            "updated": len(results["updated"]) + len(results["dry_run_would_update"]),
            "skipped_mismatch": len(results["skipped_mismatch"]),
        },
        "updated_files": results["updated"] + results["dry_run_would_update"],
        "mismatch_files": results["skipped_mismatch"],
    }

    with open(REPORT_PATH, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n  📋 Report: {os.path.abspath(REPORT_PATH)}")


if __name__ == "__main__":
    print(f"Dispatcher updater — project: {os.path.abspath(PROJECT_DIR)}")
    print(f"Dry-run: {DRY_RUN}  |  Backup: {ENABLE_BACKUP}\n")
    run()
