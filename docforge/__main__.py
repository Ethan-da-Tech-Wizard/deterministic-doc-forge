"""
DocForge Module Execution Entrypoint (`python3 -m docforge`)
============================================================

This file allows the DocForge package to be executed directly from the terminal
using Python's `-m` (module) flag:

    python3 -m docforge --help
    python3 -m docforge build -i examples/sample_project.json -o docs

Why `__main__.py` matters in Python Engineering:
------------------------------------------------
In modern Python packaging, providing a `__main__.py` enables users to execute
the package without installing it into their system `PATH` via `pip install -e .`.
This is essential for hermetic zero-dependency developer tooling: anyone who clones
the repository can immediately execute the tool using the standard system Python interpreter:

    git clone https://github.com/Ethan-da-Tech-Wizard/deterministic-doc-forge.git
    cd deterministic-doc-forge
    python3 -m docforge init

Interview Talking Point (Packaging & CLI Design):
-------------------------------------------------
When asked about Python module architecture, explain that Python executes `__main__.py`
when a package directory or zipfile is passed to the interpreter. It separates the
reusable library logic (`docforge.engine`) from the command-line execution entry point,
ensuring clean architectural decoupling.
"""

from __future__ import annotations

import sys
from docforge.cli import main

if __name__ == "__main__":
    # Hand off directly to the CLI argument dispatcher and propagate the exit code.
    sys.exit(main())
