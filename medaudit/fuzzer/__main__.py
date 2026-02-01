# Medaudit HL7 Fuzzer - Module Entry Point

"""
Allows running the fuzzer as a module:
    python -m medaudit.fuzzer [command] [options]
"""

from .cli import main
import sys

if __name__ == "__main__":
    sys.exit(main())
