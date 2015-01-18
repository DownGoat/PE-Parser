import sys
from pe_file import PEFile


if len(sys.argv) != 2:
    print("Usage: python pe_viewer.py <path_to_pe_file>")

a = PEFile(sys.argv[1])
a.print_table()
