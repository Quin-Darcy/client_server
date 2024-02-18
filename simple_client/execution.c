#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <winnt.h>
#include "execution.h"


typedef struct 
{
    uint16_t e_magic;
    uint32_t e_lfanew;
} DOSHeader;

int parse_headers(const char* payload, DWORD* image_base, DWORD* address_of_entry)
{
    printf("[+] Parsing PE headers ...\n");

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)payload;

    if (dos_header->e_magic != 0x5A4D)
    {
        fprintf(stderr, "[!] Invalid DOS header.\n");
        return 1;
    }

    IMAGE_NT_HEADERS32* nt_headers_temp = (IMAGE_NT_HEADERS32*)(payload + dos_header->e_lfanew);
    if (nt_headers_temp->Signature != IMAGE_NT_SIGNATURE) 
    {
        fprintf(stderr, "[!] Invalid NT header.\n");
        return 1;
    }

    // Check the Magic field in the OptionalHeader to determine the architecture
    if (nt_headers_temp->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) 
    {
        printf("[i] Architecture: 32-bit.\n");

        // This is a 32-bit executable
        IMAGE_NT_HEADERS32* nt_headers = nt_headers_temp;
        
        if (nt_headers->Signature != 0x4550)
        {
            fprintf(stderr, "[!] Invalid NT header.\n");
            return 1;
        }

        *address_of_entry = nt_headers->OptionalHeader.AddressOfEntryPoint;
        *image_base = nt_headers->OptionalHeader.ImageBase;

        printf("[i] Image Base: 0x%08x\n", *image_base);
        printf("[i] Entry Point Address: 0x%08x\n", *address_of_entry);
    } 
    else if (nt_headers_temp->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) 
    {
        printf("[i] Architecture: 64-bit.\n");

        // This is a 64-bit executable
        IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)nt_headers_temp;
        
        if (nt_headers->Signature != 0x4550)
        {
            fprintf(stderr, "[!] Invalid NT header.\n");
            return 1;
        }

        *address_of_entry = nt_headers->OptionalHeader.AddressOfEntryPoint;
        *image_base = nt_headers->OptionalHeader.ImageBase;

        printf("[i] Image Base: 0x%08x\n", *image_base);
        printf("[i] Entry Point Address: 0x%08x\n", *address_of_entry);
    } 
    else 
    {
        fprintf(stderr, "[!] Unknown PE format.\n");
        return 1;
    }

    return 0;
}

// Requests block of memory suitable for code execution from OS
int allocate_executable_memory(const size_t payload_size, LPVOID* image_base)
{
    printf("[+] Allocating memory for the payload ...\n");

    *image_base = VirtualAlloc(NULL, (DWORD)payload_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (*image_base == NULL)
    {
        fprintf(stderr, "[!] VirtualAlloc() failed.\n");
        return 1;
    }

    return 0;
}

// Initiates execution of the in-memory binary by jumping to its entry point
// void execute_entry_point(LPVOID image_base)
// {

// }

int execute_payload(const char* payload, const size_t payload_size)
{
    DWORD image_base;
    DWORD address_of_entry;
    if (parse_headers(payload, &image_base, &address_of_entry) != 0)
    {
        fprintf(stderr, "[!] parse_headers() failed.\n");
        return 1;
    }

    // LPVOID base_address = NULL;
    // if (allocate_executable_memory(payload_size, &base_address) != 0)
    // {
    //     fprintf(stderr, "[!] allocate_executable_memory() failed.\n");
    //     return 1;
    // }

    // printf("[+] Copying raw binary bytes into allocated memory region ...\n");
    // memcpy(base_address, payload, payload_size);

    // printf("[+] Freeing allocated memory ...\n");
    // if (!VirtualFree(base_address, (DWORD)payload_size, MEM_DECOMMIT))
    // {
    //     fprintf(stderr, "[!] VirtualFree() failed.\n");
    //     return 1;
    // }

    return 0;
}