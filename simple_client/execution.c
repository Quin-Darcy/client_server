#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <winnt.h>
#include "execution.h"

typedef struct _SECTION_INFO {
    LPVOID base_address; // The address at which the section was loaded in memory
    LPVOID preferred_address; // The address relative to ImageBase at which this section was intended to be loaded
    DWORD virtual_address; // Offset from ImageBase
    DWORD virtual_size;  // The size of the section in memory
    intptr_t delta; // Difference between the preferred load address and the actual load address
} SECTION_INFO;

typedef struct _PE_CONTEXT {
    DWORD image_base; // Preferred base address
    DWORD address_of_entry; // Address at which the entry point is located
    DWORD number_of_sections; // Number of sections
    IMAGE_SECTION_HEADER* section_headers; // Pointer to the first section header
    SECTION_INFO* sections_info; // Stores the actual base address of each section and its size
} PE_CONTEXT; 


void cleanup_context(PE_CONTEXT* pe_ctx)
{
    printf("[+] Cleaning up PE context ...\n");

    // Free the memory which was allocated to the sections_headers and sections_info members
    if (pe_ctx->section_headers != NULL)
    {
        free(pe_ctx->section_headers);
    }

    // Loop through and free all the allocated memory for each section
    for (DWORD i = 0; i < pe_ctx->number_of_sections; i++)
    {
        SECTION_INFO* current_section_info = &pe_ctx->sections_info[i];

        if (!VirtualFree(current_section_info->base_address, 0, MEM_RELEASE))
        {
            fprintf(stderr, "[!] Failed to free one of the sections.\n");
        }
    }

    // Free the memory allocated to sections_info
    if (pe_ctx->sections_info != NULL)
    {
        free(pe_ctx->sections_info);
    }
}

int validate_pe(const unsigned char* payload)
{
    printf("[+] Validating PE file ...\n");

    // Check for valid DOS signature
    const IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)payload;
    if (dos_header->e_magic != 0x5A4D)
    {
        fprintf(stderr, "[!] Invalid DOS header.\n");
        return 1;
    }

    // Check that its a valid PE 
    const IMAGE_NT_HEADERS32* nt_headers = (IMAGE_NT_HEADERS32*)(payload + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        fprintf(stderr, "[!] Invalid NT header.\n");
        return 1;
    }

    // Check its architecture
    if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) 
    {
        fprintf(stderr, "[!] 64-bit architechture detected. Please use 32-bit instead.\n");
        return 1;
    }
    else if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        fprintf(stderr, "[!] Unknown PE format.\n");
        return 1;   
    }

    printf("[i] Valid 32-bit PE file.\n");
    return 0;
}

// Function to adjust memory protection based on section characteristics
DWORD get_section_protection(DWORD characteristics) 
{
    // if (characteristics & IMAGE_SCN_MEM_EXECUTE) 
    // {
    //     if (characteristics & IMAGE_SCN_MEM_WRITE) 
    //     {
    //         return PAGE_EXECUTE_READWRITE;
    //     } 
    //     else if (characteristics & IMAGE_SCN_MEM_READ) 
    //     {
    //         return PAGE_EXECUTE_READ;
    //     } 
    //     else 
    //     {
    //         return PAGE_EXECUTE;
    //     }
    // } 
    // else if (characteristics & IMAGE_SCN_MEM_WRITE) 
    // {
    //     return PAGE_READWRITE;
    // } 
    // else if (characteristics & IMAGE_SCN_MEM_READ) 
    // {
    //     return PAGE_READONLY;
    // }
    // return PAGE_NOACCESS;

    return PAGE_EXECUTE_READWRITE;
}

// Parse the PE file and load each section individually
int load_sections(const unsigned char* payload, PE_CONTEXT* pe_ctx)
{
    printf("[+] Loading PE sections ...\n");

    // Check for valid DOS signature
    const IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)payload;
    const IMAGE_NT_HEADERS32* nt_headers = (IMAGE_NT_HEADERS32*)(payload + dos_header->e_lfanew);

    // Retrieve section alignment
    DWORD section_alignment = nt_headers->OptionalHeader.SectionAlignment;

    // Store the key pieces of information from the PE file for later access 
    pe_ctx->image_base = nt_headers->OptionalHeader.ImageBase;
    pe_ctx->address_of_entry = nt_headers->OptionalHeader.AddressOfEntryPoint;
    pe_ctx->number_of_sections = nt_headers->FileHeader.NumberOfSections; 

    printf("[i] Number of Sections: %d\n", pe_ctx->number_of_sections);
    
    // Allocate memory to store the all the section headers
    size_t section_headers_size = sizeof(IMAGE_SECTION_HEADER) * pe_ctx->number_of_sections;
    pe_ctx->section_headers = (IMAGE_SECTION_HEADER*)calloc(section_headers_size, 1);

    if (pe_ctx->section_headers == NULL)
    {
        fprintf(stderr, "[!] Failed to allocate memory for section headers.\n");
        return 1;
    }

    // Copy section_headers_size many bytes starting from the beginning of the first section header at nt_headers + 1
    memcpy(pe_ctx->section_headers, (void*)(nt_headers + 1), section_headers_size);

    // Allocate memory for the sections_info member
    size_t sections_size = sizeof(SECTION_INFO) * pe_ctx->number_of_sections;
    pe_ctx->sections_info = (SECTION_INFO*)calloc(sections_size, 1);

    if (pe_ctx->sections_info == NULL)
    {
        fprintf(stderr, "[!] Failed to allocate memory for sections info.\n");
        return 1;
    }

    // Loop through each section and map it into memory
    for (DWORD i = 0; i < pe_ctx->number_of_sections; i++)
    {
        // Capture the current header and section info
        IMAGE_SECTION_HEADER* current_section = &pe_ctx->section_headers[i];
        SECTION_INFO* current_sections_info = &pe_ctx->sections_info[i];

        // Align VirtualSize with the nearest higher multiple of section_alignment
        size_t aligned_size = (current_section->Misc.VirtualSize + section_alignment - 1) & ~(section_alignment - 1);

        // Attempt to allocate memory for it at its preferred address
        LPVOID preferred_address = (LPVOID)(pe_ctx->image_base + current_section->VirtualAddress);
        LPVOID base_addr = VirtualAlloc((LPVOID)(pe_ctx->image_base + current_section->VirtualAddress), aligned_size, MEM_COMMIT | MEM_RESERVE, get_section_protection(current_section->Characteristics));

        // If the preferred address is unavilable, let the OS decide
        if (base_addr == NULL)
        {
            base_addr = VirtualAlloc(NULL, aligned_size, MEM_COMMIT | MEM_RESERVE, get_section_protection(current_section->Characteristics));

            // If it fails again, return
            if (base_addr == NULL)
            {
                fprintf(stderr, "[!] Failed to allocate memory for the following section: %s\n", current_section->Name);
                return 1;
            }
        }

        // Update the corresponding sections_info member
        current_sections_info->base_address = base_addr;
        current_sections_info->preferred_address = preferred_address;
        current_sections_info->virtual_address = current_section->VirtualAddress;
        current_sections_info->virtual_size = current_section->Misc.VirtualSize;
        current_sections_info->delta = (intptr_t)base_addr - (intptr_t)preferred_address;

        // Copy the contents of the section into the allocated region provided they are non-zero
        if (current_section->SizeOfRawData > 0)
        {
            size_t bytes_to_copy = (size_t)min(current_section->SizeOfRawData, current_section->Misc.VirtualSize);
            // Ensure that the destination buffer is large enough for the copy operation
            if (aligned_size < bytes_to_copy) {
                fprintf(stderr, "[!] Allocated memory size is smaller than the section's raw data size for section: %s\n", current_section->Name);
                return 1; // or handle error appropriately
            }
            memcpy((void*)base_addr, (void*)(payload + current_section->PointerToRawData), bytes_to_copy);
        }
    }

    printf("[i] Sections Loaded: %lu\n", pe_ctx->number_of_sections);

    return 0;
}

// Currently debugging
int apply_relocations(const unsigned char* payload, PE_CONTEXT* pe_ctx)
{
    printf("[+] Applying relocations ...\n");

    const IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)payload;
    const IMAGE_NT_HEADERS32* nt_headers = (IMAGE_NT_HEADERS32*)(payload + dos_header->e_lfanew);

    // The relocation directory contains the address (RVA) and size of the relocation table
    const IMAGE_DATA_DIRECTORY relocation_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    if (relocation_directory.Size == 0)
    {
        printf("[i] The PE file contains no relocation entries.\n");
        return 0;
    } 

    // Determine which section contains the relocation_directory
    int found = 0;
    DWORD reloc_offset = 0;
    for (DWORD i = 0; i < pe_ctx->number_of_sections; i++) 
    {
        // Find the sections whose virtual address range contains the virtual address of the relocation directory
        IMAGE_SECTION_HEADER* section = &pe_ctx->section_headers[i];
        if (relocation_directory.VirtualAddress >= section->VirtualAddress &&
            relocation_directory.VirtualAddress < section->VirtualAddress + section->SizeOfRawData) 
        {
            // Once found, take the difference between the two RVAs which represents a virtual offset and add to it the disk offset
            // This gives the actual address in the payload (on disk) where the relocation directory can be found
            reloc_offset = section->PointerToRawData + (relocation_directory.VirtualAddress - section->VirtualAddress);
            found = 1;
            break;
        }
    }

    if (found == 0) {
        fprintf(stderr, "[!] Failed to find section containing the relocation directory.\n");
        return 1;
    }

    // To track total entries processed
    DWORD processed_size = 0;
    DWORD entries_processed = 0;
    // Point relocation block to the first block of the relocation table
    IMAGE_BASE_RELOCATION* current_block = (IMAGE_BASE_RELOCATION*)(payload + reloc_offset);

    // Iterate through relocation blocks
    while (processed_size < relocation_directory.Size)
    {
        // This size includes header and entries
        DWORD block_size = current_block->SizeOfBlock;
        DWORD page_virtual_address = current_block->VirtualAddress;

        // Loop through the sections until the one containing the page_rva is found
        DWORD section_index = (DWORD)-1;
        for (DWORD i = 0; i < pe_ctx->number_of_sections; i++)
        {
            DWORD section_virtual_address = (DWORD)pe_ctx->sections_info[i].virtual_address;
            DWORD virtual_size = (DWORD)pe_ctx->sections_info[i].virtual_size;

            if ((section_virtual_address <= page_virtual_address) && (page_virtual_address <= section_virtual_address + virtual_size))
            {
                section_index = i;
                break;
            }
        }

        if (section_index == (DWORD)-1)
        {
            fprintf(stderr, "[!] No section found for relocation block.\n");
            return 1;
        }

        // Compute the actual address of the 4KB page which this relocation block corresponds to 
        DWORD_PTR actual_page_address = (DWORD_PTR)pe_ctx->sections_info[section_index].base_address 
            + (page_virtual_address - (DWORD)pe_ctx->sections_info[section_index].virtual_address);
        // Create pointer pointing to entires right after the IMAGE_BASE_RELOCATION header
        WORD* relocation_entries = (WORD*)((DWORD_PTR)current_block + sizeof(IMAGE_BASE_RELOCATION));
        // Calculate teh number of relocation entries in this block
        DWORD num_entries = (block_size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (DWORD j = 0; j < num_entries; j++)
        {
            WORD relocation_info = relocation_entries[j];

            // Each entry is two bytes - the first 4 bits define the type of relocation
            WORD type = relocation_info >> 12;
            // The remaining 12 bits define the offset within the page
            WORD offset = relocation_info & 0x0FFF;
            // Compute the patch address
            DWORD_PTR* patch_address = (DWORD_PTR*)(actual_page_address + offset); // This needs to match the relocation type's expected size

            // Handle the case for 32-bit relocation types
            if (type == IMAGE_REL_BASED_HIGHLOW)
            {
                // Shift the patch address by the delta corresponding to this section
                *(DWORD*)patch_address += (DWORD)pe_ctx->sections_info[section_index].delta;
                entries_processed += 1;
            }
            else if (type == IMAGE_REL_BASED_ABSOLUTE)
            {
                entries_processed += 1;
                continue;
            }
            else 
            {
                fprintf(stderr, "[!] Unsupported relocation type. Relocation Info Address: %p\n", (void*)&relocation_info);
                getchar();
                return 1;
            }
        }

        // Advance forward to the next block
        current_block = (IMAGE_BASE_RELOCATION*)((unsigned char*)current_block + block_size);
        processed_size += block_size;
    }

    printf("[i] %d total addresses patched.\n", entries_processed);

    return 0;
}

int execute_payload(const unsigned char* payload, const size_t payload_size)
{
    // Validate the received payload
    if (validate_pe(payload) != 0)
    {
        fprintf(stderr, "[!] Invalid PE file received.\n");
        return 1;
    }

    // Parse the headers and load the sections into memory
    PE_CONTEXT pe_ctx;
    if (load_sections(payload, &pe_ctx) != 0)
    {
        fprintf(stderr, "[!] Load sections failed.\n");
        cleanup_context(&pe_ctx);
        return 1;
    }

    // Apply the relocations
    if (apply_relocations(payload, &pe_ctx) != 0)
    {
        fprintf(stderr, "[!] Failed to apply relocations.\n");
        cleanup_context(&pe_ctx);
        return 1;
    }

    cleanup_context(&pe_ctx);

    return 0;
}
