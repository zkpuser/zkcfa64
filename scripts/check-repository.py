#!/usr/bin/env python3
"""Check repository layout, simple Markdown links, and maintained script syntax.

Uses Git-visible working files, excluding pending deletions, vendor trees, and
submodule contents. Markdown support covers inline links/images and reference definitions,
not a full Markdown renderer; anchors, HTML links, and nested link syntax are not
validated. No scripts are executed, dependencies built, or caches written.
"""

from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {"vendor"}
INLINE_LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*(<[^>]*>|[^\s)]+)")
REFERENCE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>]*>|\S+)")


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args]).decode()


def markdown_links(source):
    fence = None
    for number, line in enumerate(source.splitlines(), 1):
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is not None or line.startswith(("    ", "\t")):
            continue
        line = re.sub(r"(`+).*?\1", "", line)
        matches = list(INLINE_LINK.finditer(line))
        reference = REFERENCE.match(line)
        if reference:
            matches.append(reference)
        for match in matches:
            yield number, match.group(1).strip("<>")


def main():
    errors = []
    index = git("ls-files", "--stage", "-z").split("\0")
    submodules = {row.split("\t", 1)[1] for row in index if row.startswith("160000 ")}
    config = subprocess.run(
        ["git", "config", "--file", str(ROOT / ".gitmodules"),
         "--get-regexp", r"^submodule\..*\.path$"],
        capture_output=True, text=True,
    )
    if config.returncode not in (0, 1):
        errors.append(f"Cannot read .gitmodules: {config.stderr.strip()}")
    configured = [line.split(None, 1)[1] for line in config.stdout.splitlines()]
    if set(configured) != submodules or len(configured) != len(set(configured)):
        errors.append(f".gitmodules paths {sorted(configured)} differ from gitlinks {sorted(submodules)}")

    files = set(git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split("\0")) - {""}
    files -= set(git("ls-files", "--deleted", "-z").split("\0"))
    directories = {str(parent) for name in files for parent in PurePosixPath(name).parents}
    visible = files | directories
    counts = {"Markdown": 0, "local links": 0, "Python": 0, "shell": 0}

    def in_submodule(name):
        return any(name == path or name.startswith(path + "/") for path in submodules)

    for name in sorted(files):
        path = ROOT / name
        if EXCLUDED_DIRS.intersection(PurePosixPath(name).parts) or in_submodule(name):
            continue
        try:
            if name.endswith(".md"):
                counts["Markdown"] += 1
                for number, link in markdown_links(path.read_text(encoding="utf-8")):
                    parsed = urlsplit(link)
                    if parsed.scheme or parsed.netloc or not parsed.path:
                        continue
                    target = posixpath.normpath(posixpath.join(posixpath.dirname(name), unquote(parsed.path)))
                    if in_submodule(target):
                        continue
                    counts["local links"] += 1
                    if target not in visible or not (ROOT / target).exists():
                        errors.append(f"{name}:{number}: local link is not a Git-visible target: {link}")
            elif name.endswith(".py"):
                counts["Python"] += 1
                compile(path.read_bytes(), name, "exec")
            elif name.endswith(".sh"):
                counts["shell"] += 1
                result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
                if result.returncode:
                    errors.append(f"{name}: {result.stderr.strip()}")
        except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
            errors.append(f"{name}: {exc}")

    summary = ", ".join(f"{value} {key}" for key, value in counts.items())
    print(f"Checked {len(submodules)} submodule paths; {summary}.")
    print("Excluded vendor trees and submodule contents; Markdown anchors/HTML/nested syntax are not checked.")
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    print(f"Repository check {'FAILED' if errors else 'PASSED'} ({len(errors)} errors).")
    return int(bool(errors))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Repository check could not run: {exc}", file=sys.stderr)
        sys.exit(1)
