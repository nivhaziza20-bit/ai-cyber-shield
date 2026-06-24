"""
Adds the project root to sys.path so all test modules can import
top-level packages (config, tools, agents, orchestrator) without
needing an editable install.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
