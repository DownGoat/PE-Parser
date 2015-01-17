import sys


def dump(the_string):
    hex_str = ""

    for x in range(len(the_string)):
        hex_str += format(the_string[x], "02x")

        if x != 0 and x % 16 == 0:
            hex_str += "\n"

    print(hex_str)


class ParserError(Exception):
    pass


class Section():
    pass


class PEFile():
    def __init__(self, pe_file=None):
        self.pe_file = pe_file

        if self.pe_file != None:
            self.parse(self.pe_file)

    def open_pe(self):
        pe_data = None

        try:
            h = open(self.pe_file, "rb")
            pe_data = h.read()
            h.close()
        except IOError as error:
            print(error)
            sys.exit(0)

        return pe_data

    def get_value_int(self, pe_data, offset, limit):
        return int.from_bytes(pe_data[offset:offset + limit], byteorder="little")

    def get_value_str(self, pe_data, offset, limit):
        return str(pe_data[offset:offset + limit], "ascii")

    def print_table(self):
        table_width = 20
        column_width = 15

        print("\n+-------#DOS HEADER---------------------------------+")
        print("| {0: <30} | {1: <16} |".format("e_magic", self.e_magic))
        print("| {0: <30} | {1: <16} |".format("e_lfanew", "0x%X" % self.e_lfanew))
        print("+-------#PE HEADER#---------------------------------+")
        print("| {0: <30} | {1: <16} |".format("Signature", "0x%X" % self.pe_signature))
        print("| {0: <30} | {1: <16} |".format("Machine", "0x%X" % self.pe_machine))
        print("| {0: <30} | {1: <16} |".format("NumberOfSections", "0x%X" % self.pe_number_of_sections))
        print("| {0: <30} | {1: <16} |".format("TimeDateStamp", "0x%X" % self.pe_time_date_stamp))
        print("| {0: <30} | {1: <16} |".format("PointerToSymbolTable", "0x%X" % self.pe_pointer_to_symbol_table))
        print("| {0: <30} | {1: <16} |".format("NumberOfSymbols", "0x%X" % self.pe_number_of_symbols))
        print("| {0: <30} | {1: <16} |".format("SizeOfOptionalHeader", "0x%X" % self.pe_size_of_optional_header))
        print("| {0: <30} | {1: <16} |".format("Characteristics", "0x%X" % self.pe_characteristics))
        print("+-------#OPTIONAL HEADER#---------------------------+")
        print("| {0: <30} | {1: <16} |".format("Magic", "0x%X" % self.magic))
        print("| {0: <30} | {1: <16} |".format("MajorLinkerVersion", "0x%X" % self.major_linker_version))
        print("| {0: <30} | {1: <16} |".format("MinorLinkerVersion", "0x%X" % self.minor_linker_version))
        print("| {0: <30} | {1: <16} |".format("SizeOfCode", "0x%X" % self.size_of_code))
        print("| {0: <30} | {1: <16} |".format("SizeOfInitializedData", "0x%X" % self.size_of_initialized_data))
        print("| {0: <30} | {1: <16} |".format("SizeOfUninitializedData", "0x%X" % self.size_of_uninitialized_data))
        print("| {0: <30} | {1: <16} |".format("AddressOfEntryPoint", "0x%X" % self.address_of_entry_point))
        print("| {0: <30} | {1: <16} |".format("BaseOfCode", "0x%X" % self.base_of_code))
        print("| {0: <30} | {1: <16} |".format("BaseOfData", "0x%X" % self.base_of_data))
        print("| {0: <30} | {1: <16} |".format("ImageBase", "0x%X" % self.image_base))
        print("| {0: <30} | {1: <16} |".format("SectionalAlignment", "0x%X" % self.sectional_alignment))
        print("| {0: <30} | {1: <16} |".format("FileAlignment", "0x%X" % self.file_alignment))
        print("| {0: <30} | {1: <16} |".format("MajorOperatingSystemVersion", "0x%X" % self.major_operating_system_version))
        print("| {0: <30} | {1: <16} |".format("MinorOperatingSystemVersion", "0x%X" % self.minor_operating_system_version))
        print("| {0: <30} | {1: <16} |".format("MajorImageVersion", "0x%X" % self.major_image_version))
        print("| {0: <30} | {1: <16} |".format("MinorImageVersion", "0x%X" % self.minor_image_version))
        print("| {0: <30} | {1: <16} |".format("MajorSubsystemVersion", "0x%X" % self.major_subsystem_version))
        print("| {0: <30} | {1: <16} |".format("MinorSubsystemVersion", "0x%X" % self.minor_subsystem_version))
        print("| {0: <30} | {1: <16} |".format("Win32VersionValue", "0x%X" % self.win32_version_value))
        print("| {0: <30} | {1: <16} |".format("SizeOfImage", "0x%X" % self.size_of_image))
        print("| {0: <30} | {1: <16} |".format("SizeOfHeaders", "0x%X" % self.size_of_headers))
        print("| {0: <30} | {1: <16} |".format("Checksum", "0x%X" % self.checksum))
        print("| {0: <30} | {1: <16} |".format("Subsystem", "0x%X" % self.subsystem))
        print("| {0: <30} | {1: <16} |".format("DllCharacteristics", "0x%X" % self.dll_characteristics))
        print("| {0: <30} | {1: <16} |".format("SizeOfStackReserve", "0x%X" % self.size_of_stack_reserve))
        print("| {0: <30} | {1: <16} |".format("SizeOfStackCommit", "0x%X" % self.size_of_stack_commit))
        print("| {0: <30} | {1: <16} |".format("SizeOfHeapReserve", "0x%X" % self.size_of_heap_reserve))
        print("| {0: <30} | {1: <16} |".format("SizeOfHeapCommit", "0x%X" % self.size_of_heap_commit))
        print("| {0: <30} | {1: <16} |".format("LoaderFlags", "0x%X" % self.loader_flags))
        print("| {0: <30} | {1: <16} |".format("NumberOfRvaAndSizes", "0x%X" % self.number_of_rva_and_sizes))
        print("+------#SECTIONS#-----------------------------------+")

        for sec in self.sections:
            print("| {0: <30} | {1: <19} |".format("Name", "%s" % sec.name))
            print("| {0: <30} | {1: <16} |".format("Misc.VirtualSize", "0x%X" % sec.misc_virtual_size))
            print("| {0: <30} | {1: <16} |".format("VirtualAddress", "0x%X" % sec.virtual_address))
            print("| {0: <30} | {1: <16} |".format("SizeOfRawData", "0x%X" % sec.size_of_raw_data))
            print("| {0: <30} | {1: <16} |".format("PointerToRawData", "0x%X" % sec.pointer_to_raw_data))
            print("| {0: <30} | {1: <16} |".format("PointerToRelocations", "0x%X" % sec.pointer_to_relocations))
            print("| {0: <30} | {1: <16} |".format("PointerToLinenumbers", "0x%X" % sec.pointer_to_linenumbers))
            print("| {0: <30} | {1: <16} |".format("NumberOfRelocations", "0x%X" % sec.number_of_relocations))
            print("| {0: <30} | {1: <16} |".format("NumberOfLinenumbers", "0x%X" % sec.number_of_linenumbers))
            print("| {0: <30} | {1: <16} |".format("Characteristics", "0x%X" % sec.characteristics))
            print("+---------------------------------------------------+")

    def parse_dos_header(self, pe_data):
        self.e_magic = self.get_value_str(pe_data, 0, 2)

        if self.e_magic != "MZ":
            raise ParserError("File is not a PE file.")

        offset = int("0x3c", 16)
        self.e_lfanew = self.get_value_int(pe_data, offset, 4)

        if self.e_lfanew == 0:
            raise ParserError("PE header offset is 0, this is propably not a PE file.")
            sys.exit(0)

    def parse_pe_header(self, pe_data):
        offset = self.e_lfanew
        self.pe_signature = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.pe_machine = self.get_value_int(pe_data, offset, 2)
        if self.pe_machine != int("0x014c", 16) and self.pe_machine != int("0x0200", 16) and self.pe_machine != int("0x8664", 16):
            raise ParserError("Machine member has value %d" % self.pe_machine)

        offset += 2
        self.pe_number_of_sections = self.get_value_int(pe_data, offset, 2)
        if self.pe_number_of_sections > 96:
            raise ParserError("NumberOfSections member has a value that is greater than 96\n")

        offset += 2
        self.pe_time_date_stamp = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.pe_pointer_to_symbol_table = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.pe_number_of_symbols = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.pe_size_of_optional_header = self.get_value_int(pe_data, offset, 2)

        offset += 2
        self.pe_characteristics = self.get_value_int(pe_data, offset, 2)
        # Unsure about how to check if the value is correct.
        # http://msdn.microsoft.com/en-us/library/windows/desktop/ms680313%28v=vs.85%29.aspx

    def parse_optional_header(self, pe_data):
        offset = self.e_lfanew + 24

        self.magic = self.get_value_int(pe_data, offset, 2)
        if self.magic != int("0x10b", 16) and self.magic != int("0x20b", 16) and self.magic != int("0x107", 16):
            raise ParserError("Magic member has value %d." % self.magic)

        offset += 2
        self.major_linker_version = self.get_value_int(pe_data, offset, 1)

        offset += 1
        self.minor_linker_version = self.get_value_int(pe_data, offset, 1)

        offset += 1
        self.size_of_code = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.size_of_initialized_data = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.size_of_uninitialized_data = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.address_of_entry_point = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.base_of_code = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.base_of_data = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.image_base = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.sectional_alignment = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.file_alignment = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.major_operating_system_version = self.get_value_int(pe_data, offset, 2)

        offset += 2
        self.minor_operating_system_version = self.get_value_int(pe_data, offset, 2)

        offset += 2
        self.major_image_version = self.get_value_int(pe_data, offset, 2)

        offset += 2
        self.minor_image_version = self.get_value_int(pe_data, offset, 2)

        offset += 2
        self.major_subsystem_version = self.get_value_int(pe_data, offset, 2)

        offset += 2
        self.minor_subsystem_version = self.get_value_int(pe_data, offset, 2)

        offset += 2
        self.win32_version_value = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.size_of_image = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.size_of_headers = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.checksum = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.subsystem = self.get_value_int(pe_data, offset, 2)
        if self.subsystem >= 0 or self.subsystem <= 16:
            if self.subsystem == 4 or self.subsystem == 6 or self.subsystem == 8 or self.subsystem == 15:
                raise ParserError("Subsystem member has value %d" % self.subsystem)

        offset += 2
        self.dll_characteristics = self.get_value_int(pe_data, offset, 2)
        if self.dll_characteristics != int("0x0001", 16) and self.dll_characteristics != int("0x0002", 16) and \
                self.dll_characteristics != int("0x0004", 16) and self.dll_characteristics != int("0x0008", 16) and \
                self.dll_characteristics != int("0x0040", 16) and self.dll_characteristics != int("0x0080", 16) and \
                self.dll_characteristics != int("0x0100", 16) and self.dll_characteristics != int("0x0200", 16) and \
                self.dll_characteristics != int("0x0400", 16) and self.dll_characteristics != int("0x0800", 16) and \
                self.dll_characteristics != int("0x1000", 16) and self.dll_characteristics != int("0x2000", 16) and \
                self.dll_characteristics != int("0x4000", 16) and self.dll_characteristics != int("0x8000", 16) and \
                self.dll_characteristics != 0:
                    raise ParserError("DLLCharacteristics member has value %d." % self.dll_characteristics)

        offset += 2
        self.size_of_stack_reserve = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.size_of_stack_commit = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.size_of_heap_reserve = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.size_of_heap_commit = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.loader_flags = self.get_value_int(pe_data, offset, 4)

        offset += 4
        self.number_of_rva_and_sizes = self.get_value_int(pe_data, offset, 4)

    def parse_section_table(self, pe_data):
        self.sections = []
        offset = self.e_lfanew + 24 + self.pe_size_of_optional_header

        for x in range(self.pe_number_of_sections):
            sec = Section()
            sec.name = self.get_value_str(pe_data, offset, 8)

            offset += 8
            sec.misc_virtual_size = self.get_value_int(pe_data, offset, 4)

            offset += 4
            sec.virtual_address = self.get_value_int(pe_data, offset, 4)

            offset += 4
            sec.size_of_raw_data = self.get_value_int(pe_data, offset, 4)

            offset += 4
            sec.pointer_to_raw_data = self.get_value_int(pe_data, offset, 4)

            offset += 4
            sec.pointer_to_relocations = self.get_value_int(pe_data, offset, 4)

            offset += 4
            sec.pointer_to_linenumbers = self.get_value_int(pe_data, offset, 4)

            offset += 4
            sec.number_of_relocations = self.get_value_int(pe_data, offset, 2)

            offset += 2
            sec.number_of_linenumbers = self.get_value_int(pe_data, offset, 2)

            offset += 2
            sec.characteristics = self.get_value_int(pe_data, offset, 4)

            offset += 4
            self.sections.append(sec)


    def parse(self, pe_file):
        self.pe_file = pe_file

        pe_data = self.open_pe()

        self.parse_dos_header(pe_data)
        self.parse_pe_header(pe_data)
        self.parse_optional_header(pe_data)
        self.parse_section_table(pe_data)
        self.print_table()
