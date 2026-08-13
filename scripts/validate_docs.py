"""Validate repository-local documentation links and documented task commands."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_FILES = (
    REPOSITORY_ROOT / "README.md",
    REPOSITORY_ROOT / "ROADMAP.md",
    REPOSITORY_ROOT / "CHANGELOG.md",
    REPOSITORY_ROOT / "SECURITY.md",
    *sorted((REPOSITORY_ROOT / "docs").rglob("*.md")),
)
LOCAL_LINK_PATTERN = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")
REQUIRED_MAKE_TARGETS = {"audit", "compose-validate", "docs-validate", "package-build", "sbom"}


def local_link_target(source: Path, raw_target: str) -> Path | None:
    target = raw_target.split("#", maxsplit=1)[0].strip()
    if not target or "://" in target or target.startswith("mailto:"):
        return None
    return (source.parent / target).resolve()


def main() -> int:
    errors: list[str] = []
    for markdown_file in MARKDOWN_FILES:
        text = markdown_file.read_text(encoding="utf-8")
        for raw_target in LOCAL_LINK_PATTERN.findall(text):
            target = local_link_target(markdown_file, raw_target)
            if target is not None and not target.exists():
                source = markdown_file.relative_to(REPOSITORY_ROOT)
                errors.append(f"{source}: missing link target {raw_target!r}")

    makefile = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")
    available_targets = set(re.findall(r"^([a-z][a-z-]+):", makefile, flags=re.MULTILINE))
    missing_targets = REQUIRED_MAKE_TARGETS - available_targets
    if missing_targets:
        errors.append(f"Makefile missing documented targets: {', '.join(sorted(missing_targets))}")

    if errors:
        print("Documentation validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1

    print(f"Validated {len(MARKDOWN_FILES)} Markdown files and documented task commands.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
