#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <winnt.h>
#include "execution.h"

typedef struct _SECTION_INFO {
    LPVOID base_address; // The address at which the section was loaded in memory
    LPVOID preferred_address; // The RVA at which this section was intended to be loaded
    DWORD section_size;  // The size of the section in memory
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
    printf("[+] Cleaning up ...\n");

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

// Parse the PE file and load each section individually
int load_sections(const unsigned char* payload, PE_CONTEXT* pe_ctx)
{
    printf("[+] Loading PE sections ...\n");

    // Check for valid DOS signature
    const IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)payload;
    const IMAGE_NT_HEADERS32* nt_headers = (IMAGE_NT_HEADERS32*)(payload + dos_header->e_lfanew);

    printf("[i] Payload Address: %p\n", (void*)payload);

    printf("[i] PE Image Base: 0x%lX\n", (unsigned long)nt_headers->OptionalHeader.ImageBase);

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

        // Attempt to allocate memory for it at its preferred address
        LPVOID preferred_address = (LPVOID)(pe_ctx->image_base + current_section->VirtualAddress);
        LPVOID base_addr = VirtualAlloc(preferred_address, (size_t)current_section->Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        // If the preferred address is unavilable, let the OS decide
        if (base_addr == NULL)
        {
            base_addr = VirtualAlloc(NULL, (size_t)current_section->Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

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
        current_sections_info->section_size = current_section->Misc.VirtualSize;
        current_sections_info->delta = (intptr_t)base_addr - (intptr_t)preferred_address;

        // Copy the contents of the section into the allocated region provided they are non-zero
        if (current_section->SizeOfRawData > 0)
        {
            size_t bytes_to_copy = (size_t)min(current_section->SizeOfRawData, current_section->Misc.VirtualSize);
            printf("[i] Disk Address for %s: %p\n", current_section->Name, (void*)(payload + current_section->PointerToRawData));
            memcpy(base_addr, (void*)(payload + current_section->PointerToRawData), bytes_to_copy);
        }

        printf("[i] Section %d: %s\n", i+1, current_section->Name);
        printf("    Preferred Address: 0x%p\n", preferred_address);
        printf("    Actual Base Address: 0x%p\n", base_addr);
        printf("    Size: %lu bytes\n", (unsigned long)current_sections_info->section_size);
        printf("    Delta: %ld\n", (long)current_sections_info->delta);
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

    printf("[i] DOS Header at: %p\n", (void*)dos_header);
    printf("[i] NT Headers at: %p\n", (void*)nt_headers);

    // The relocation directory contains the address (RVA) and size of the relocation table
    const IMAGE_DATA_DIRECTORY relocation_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    if (relocation_directory.Size == 0)
    {
        printf("[i] The PE file contains no relocation entries.\n");
        return 0;
    } 

    printf("[i] Relocation Directory at RVA: 0x%X, Size: %lu bytes\n", relocation_directory.VirtualAddress, relocation_directory.Size);

    // To track total blocks stepped through
    DWORD num_blocks = 0;
    DWORD processed_size = 0;
    // Point relocation block to the first block of the relocation table
    IMAGE_BASE_RELOCATION* current_block = (IMAGE_BASE_RELOCATION*)((DWORD)payload + relocation_directory.VirtualAddress);

    printf("[i] First Relocation Block at: %p\n", (void*)current_block);

    getchar();

    // Iterate through relocation blocks
    while (processed_size < relocation_directory.Size)
    {
        // This size includes header and entries
        DWORD block_size = current_block->SizeOfBlock;
        DWORD page_rva = current_block->VirtualAddress;
        DWORD preferred_page_address = pe_ctx->image_base + page_rva;

        printf("[i] Number of Sections: %d\n", pe_ctx->number_of_sections);

        // Loop through the sections until the one containing the page_rva is found
        DWORD section_index = (DWORD)-1;
        for (DWORD i = 0; i < pe_ctx->number_of_sections; i++)
        {
            printf("3\n");
            DWORD section_preferred_address = (DWORD)pe_ctx->sections_info[i].preferred_address;
            DWORD section_size = (DWORD)pe_ctx->sections_info[i].section_size;

            if ((section_preferred_address <= preferred_page_address) && (preferred_page_address <= section_preferred_address + section_size))
            {
                section_index = i;
                break;
            }
        }

        printf("4\n");

        if (section_index == (DWORD)-1)
        {
            fprintf(stderr, "[!] No section found for relocation block.\n");
            return 1;
        }

        // Compute the actual address of the 4KB page which this relocation block corresponds to 
        DWORD_PTR actual_page_address = (DWORD_PTR)pe_ctx->sections_info[section_index].base_address 
            + (page_rva - (DWORD)pe_ctx->sections_info[section_index].preferred_address);
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
            }
            else 
            {
                fprintf(stderr, "[!] Unsupported relocation type.\n");
                return 1;
            }
        }

        // Advance forward to the next block
        current_block = (IMAGE_BASE_RELOCATION*)((unsigned char*)current_block + block_size);
        processed_size += block_size;
        num_blocks += 1;
    }

    printf("[i] %d total relocation blocks processed.\n", num_blocks);

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
