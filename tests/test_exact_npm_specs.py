"""Every npm spec this package hands to Reflex is an EXACT, single version.

Reflex collects every component's library/add_imports/lib_dependencies spec into
a Python set and runs ONE `bun add` with them. When the same package appears
both bare ("@clerk/clerk-react") and versioned (a consumer pinning
"@clerk/clerk-react@5.61.3"), bun keeps whichever comes FIRST, and set order
changes with the per-process hash seed (MEASURED 2026-10-02: a consumer's
frozen prod build failed while the same commit's test build passed). Declaring
the exact version here removes the bare spec, so the order cannot matter.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "custom_components" / "reflex_clerk_api"
SPEC = re.compile(r'"(@clerk/clerk-react(?:@[^"]*)?)"')
DOC_CODE = re.compile(r"``.*?``", re.S)
EXACT = re.compile(r"^@clerk/clerk-react@\d+\.\d+\.\d+$")


def _specs() -> list[tuple[str, str]]:
    out = []
    for p in sorted(SRC.glob("*.py")):
        for spec in SPEC.findall(DOC_CODE.sub("", p.read_text())):
            out.append((p.name, spec))
    return out


def test_specs_were_found() -> None:
    assert len(_specs()) >= 2, "scan found too few specs (guard against a silent no-op)"


def test_every_clerk_spec_is_exact_and_identical() -> None:
    specs = _specs()
    bad = [(f, s) for f, s in specs if not EXACT.match(s)]
    assert not bad, f"non-exact @clerk/clerk-react specs: {bad}"
    assert len({s for _, s in specs}) == 1, f"specs disagree: {specs}"
