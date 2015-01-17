There exists better tools for working with PE files, such as https://code.google.com/p/pefile/
This project is simply for my own amusement, and to understand the format better.


Usage: python pe_viewer.py <path_to_pe_file>

Output:
```
+-------#DOS HEADER---------------------------------+
| e_magic                        | MZ               |
| e_lfanew                       | 0xF8             |
+-------#PE HEADER#---------------------------------+
| Signature                      | 0x4550           |
| Machine                        | 0x14C            |
| NumberOfSections               | 0x4              |
| TimeDateStamp                  | 0x52012E86       |
| PointerToSymbolTable           | 0x0              |
| NumberOfSymbols                | 0x0              |
| SizeOfOptionalHeader           | 0xE0             |
| Characteristics                | 0x10F            |
+-------#OPTIONAL HEADER#---------------------------+
| Magic                          | 0x10B            |
| MajorLinkerVersion             | 0x7              |
| MinorLinkerVersion             | 0xA              |
| SizeOfCode                     | 0x56000          |
| SizeOfInitializedData          | 0x26000          |
| SizeOfUninitializedData        | 0x0              |
| AddressOfEntryPoint            | 0x4F125          |
| BaseOfCode                     | 0x1000           |
| BaseOfData                     | 0x57000          |
| ImageBase                      | 0x400000         |
| SectionalAlignment             | 0x1000           |
| FileAlignment                  | 0x1000           |
| MajorOperatingSystemVersion    | 0x4              |
| MinorOperatingSystemVersion    | 0x0              |
| MajorImageVersion              | 0x0              |
| MinorImageVersion              | 0x0              |
| MajorSubsystemVersion          | 0x4              |
| MinorSubsystemVersion          | 0x0              |
| Win32VersionValue              | 0x0              |
| SizeOfImage                    | 0x7D000          |
| SizeOfHeaders                  | 0x1000           |
| Checksum                       | 0x0              |
| Subsystem                      | 0x2              |
| DllCharacteristics             | 0x0              |
| SizeOfStackReserve             | 0x100000         |
| SizeOfStackCommit              | 0x1000           |
| SizeOfHeapReserve              | 0x100000         |
| SizeOfHeapCommit               | 0x1000           |
| LoaderFlags                    | 0x0              |
| NumberOfRvaAndSizes            | 0x10             |
+------#SECTIONS#-----------------------------------+
| Name                           | .text            |
| Misc.VirtualSize               | 0x55FB1          |
| VirtualAddress                 | 0x1000           |
| SizeOfRawData                  | 0x56000          |
| PointerToRawData               | 0x1000           |
| PointerToRelocations           | 0x0              |
| PointerToLinenumbers           | 0x0              |
| NumberOfRelocations            | 0x0              |
| NumberOfLinenumbers            | 0x0              |
| Characteristics                | 0x60000020       |
+---------------------------------------------------+
| Name                           | .rdata            |
| Misc.VirtualSize               | 0x1B62A          |
| VirtualAddress                 | 0x57000          |
| SizeOfRawData                  | 0x1C000          |
| PointerToRawData               | 0x57000          |
| PointerToRelocations           | 0x0              |
| PointerToLinenumbers           | 0x0              |
| NumberOfRelocations            | 0x0              |
| NumberOfLinenumbers            | 0x0              |
| Characteristics                | 0x40000040       |
+---------------------------------------------------+
| Name                           | .data            |
| Misc.VirtualSize               | 0x58C4           |
| VirtualAddress                 | 0x73000          |
| SizeOfRawData                  | 0x2000           |
| PointerToRawData               | 0x73000          |
| PointerToRelocations           | 0x0              |
| PointerToLinenumbers           | 0x0              |
| NumberOfRelocations            | 0x0              |
| NumberOfLinenumbers            | 0x0              |
| Characteristics                | 0xC0000040       |
+---------------------------------------------------+
| Name                           | .rsrc            |
| Misc.VirtualSize               | 0x3B90           |
| VirtualAddress                 | 0x79000          |
| SizeOfRawData                  | 0x4000           |
| PointerToRawData               | 0x75000          |
| PointerToRelocations           | 0x0              |
| PointerToLinenumbers           | 0x0              |
| NumberOfRelocations            | 0x0              |
| NumberOfLinenumbers            | 0x0              |
| Characteristics                | 0x40000040       |
+---------------------------------------------------+
```
