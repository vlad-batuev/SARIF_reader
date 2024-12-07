import sys
from pathlib import Path
from src.sarif import SarifParser


def main():
    start_parse = SarifParser(file_path=Path('scan.sarif'))
    start_parse()


if __name__ == "__main__":
    sys.exit(main())
