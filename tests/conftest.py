"""Pytest bootstrap: put the src/ package dir on sys.path so tests can
`import fluxguard_config`, `import fluxguard_bpf`, etc. after the repo reorg
(code lives in src/, tests live in tests/)."""
import os
import sys

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
