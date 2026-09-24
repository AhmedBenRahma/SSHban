"""Make the project root importable so `import sshban` works under bare `pytest`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
