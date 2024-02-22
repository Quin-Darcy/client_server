/*
void apply_relocations(const DWORD image_base, const LPVOID base_address)
{
    printf("[+] Applying relocations ...\n");

    const IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)((unsigned char*)base_address);
    const IMAGE_NT_HEADERS32* nt_headers = (IMAGE_NT_HEADERS32*)((unsigned char*)base_address + dos_header->e_lfanew);

    // The relocation directory contains the address (RVA) and size of the relocation table
    const IMAGE_DATA_DIRECTORY relocation_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    // Relocation table entries specify an offset within its 4KB page and the type of adjustment to be made.
    const IMAGE_BASE_RELOCATION* relocation_table = (IMAGE_BASE_RELOCATION*)((unsigned char*)base_address + relocation_directory.VirtualAddress);
    // Calculate the base relocation delta - to be used for adjusting relocation entries
    const LONG delta = (LONG)((DWORD)base_address - image_base); // LONG since diff could be < 0

    printf("[i] Delta: %d\n", delta);

    if (relocation_directory.Size == 0)
    {
        printf("[i] The PE file contains no relocation entries.\n");
    }

    // Loop through entries and apply adjustments
    DWORD total_size = 0;
    DWORD relocation_blocks = 0;
    while (total_size < relocation_directory.Size)
    {
        // Total size of the relocation block, including the header
        DWORD block_size = relocation_table->SizeOfBlock;
        // Number of 16-bit relocation entries which follow the header
        DWORD entry_count = (block_size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        // Pointer to the first relocation entry in the block, treated as an array of WORD values
        WORD* relocation_entries = (WORD*)((unsigned char*)relocation_table + sizeof(IMAGE_BASE_RELOCATION));
    
        for (DWORD i = 0; i < entry_count; i ++) 
        {
            // Capture the current entry
            WORD entry = relocation_entries[i];
            // The first 4 bits specifies the 'type' of relocation to perform
            DWORD entry_type = entry >> 12;
            // The last 12 bits specify the offset
            DWORD entry_offset = entry & 0x0FFF;

            if (entry_type == IMAGE_REL_BASED_HIGHLOW)
            {
                // Address where the relocation needs to be applied
                DWORD* patch_address = (DWORD*)((unsigned char*)base_address + relocation_table->VirtualAddress + entry_offset);
                // Apply the relocation by adding the delta
                *patch_address += delta;
            }
            // Possible support for other relocation types
        }

        // Advance to the next block
        total_size += block_size;
        relocation_table = (IMAGE_BASE_RELOCATION*)((unsigned char*)relocation_table + block_size);
        relocation_blocks += 1;
    }

    printf("[i] %lu relocation blocks processed.\n", relocation_blocks);
}

int resolve_imports(const unsigned char* base_address)
{
    printf("[+] Resolving imports ...\n");

    // Locate the import directory which points to an array of IMAGE_IMPORT_DESCRIPTOR structs
    const IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)(base_address);
    const IMAGE_NT_HEADERS32* nt_headers = (IMAGE_NT_HEADERS32*)(base_address + dos_header->e_lfanew);
    const IMAGE_OPTIONAL_HEADER* optional_header = &nt_headers->OptionalHeader;
    const IMAGE_DATA_DIRECTORY* import_directory = &optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    // Check if there are even any imports to resolve
    if (import_directory->Size == 0) 
    {
        printf("[i] No imports to resolve.\n");
        return 0;
    }

    // Each IMAGE_IMPORT_DESCRIPTOR corresponds to a DLL from which functions are imported
    const IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (const IMAGE_IMPORT_DESCRIPTOR*)(base_address + import_directory->VirtualAddress);

    // Iterate throught each 
    while (import_descriptor->Name != 0)
    {
        // Load the library from which the functions are imported
        const char* dll_name = (const char*)(base_address + import_descriptor->Name);
        printf("[i] Import Descriptor Name: %s\n", dll_name);
        HMODULE dll_module = LoadLibraryA((LPCSTR)dll_name);
        if (dll_module == NULL)
        {
            fprintf(stderr, "[!] Failed to load %s.\n", dll_name);
            return 1;
        }

        // Patch the IAT by replacing each placeholder with the actual address of the imported function
        IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(base_address + import_descriptor->FirstThunk);
        while (thunk->u1.Function != 0) 
        {
            if (IMAGE_SNAP_BY_ORDINAL32(thunk->u1.Ordinal)) 
            {
                FARPROC proc_address = GetProcAddress(dll_module, (LPCSTR)IMAGE_ORDINAL32(thunk->u1.Ordinal));
                if (proc_address == NULL) 
                {
                    fprintf(stderr, "[!] GetProcAddress() failed for ordinal %lu.\n", (ULONG)IMAGE_ORDINAL32(thunk->u1.Ordinal));
                    return 1;
                }
                thunk->u1.Function = (ULONG_PTR)proc_address;
            } 
            else 
            {
                IMAGE_IMPORT_BY_NAME* import_by_name = (IMAGE_IMPORT_BY_NAME*)(base_address + thunk->u1.AddressOfData);
                FARPROC proc_address = GetProcAddress(dll_module, import_by_name->Name);
                if (proc_address == NULL) 
                {
                    fprintf(stderr, "[!] GetProcAddress() failed for %s.\n", import_by_name->Name);
                    return 1;
                }
                thunk->u1.Function = (ULONG_PTR)proc_address;
            }
            thunk += 1;
        }
        import_descriptor += 1;
    }

    return 0;
}
*/