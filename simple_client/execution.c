#include <errno.h>
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


// Retrieve ImageBase and AddressOfEntryPoint
int parse_headers(const unsigned char* payload, DWORD* image_base, DWORD* address_of_entry) 
{
    printf("[+] Parsing PE headers ...\n");

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)payload;

    if (dos_header->e_magic != 0x5A4D) 
    {
        fprintf(stderr, "[!] Invalid DOS header.\n");
        return 1;
    }

    IMAGE_NT_HEADERS32* nt_headers = (IMAGE_NT_HEADERS32*)(payload + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) 
    {
        fprintf(stderr, "[!] Invalid NT header.\n");
        return 1;
    }

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

    *address_of_entry = nt_headers->OptionalHeader.AddressOfEntryPoint;
    *image_base = nt_headers->OptionalHeader.ImageBase;

    printf("[i] Image Base: 0x%08x\n", *image_base);
    printf("[i] Entry Point Address: 0x%08x\n", *address_of_entry);

    return 0;
}

// First attempts to allocate memory block at the EXE's ImageBase. If the memory can not be 
// allocated at this address, a second attempt is made where the OS choses the allocation address.
int allocate_executable_memory(const size_t payload_size, const DWORD image_base, LPVOID* base_address)
{
    printf("[+] Allocating memory for the payload at 0x%08x ...\n", image_base);

    // Attempt to allocate memory at the Images's preferred address, ImageBase
    *base_address = VirtualAlloc((LPVOID)image_base, (DWORD)payload_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (*base_address == NULL || *base_address != (LPVOID)image_base)
    {
        fprintf(stderr, "[*] VirtualAlloc() failed to allocate at specified address.\n", image_base);
        
        printf("[+] Allocating memory at OS chosen address ...\n");

        *base_address = VirtualAlloc(NULL, (DWORD)payload_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (*base_address == NULL)
        {
            fprintf(stderr, "[!] VirtualAlloc() failed.\n");
            return -1;
        }

        // 1 indicates memory allocated successfully but relocations need to be made
        return 1;
    }

    return 0;
}

int fix_relocations(unsigned char* payload, const size_t payload_size, const DWORD image_base, const LPVOID base_address)
{
    // printf("[+] Fixing relocations ...\n");

    // IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)payload;
    // IMAGE_NT_HEADERS32* nt_headers = (IMAGE_NT_HEADERS32*)(payload + dos_header->e_lfanew);
    return 0;

}

// Initiates execution of the in-memory binary by jumping to its entry point
// void execute_entry_point(LPVOID image_base)
// {

// }

int execute_payload(const unsigned char* payload, const size_t payload_size)
{
    DWORD image_base;
    DWORD address_of_entry;
    if (parse_headers(payload, &image_base, &address_of_entry) != 0)
    {
        fprintf(stderr, "[!] parse_headers() failed.\n");
        return 1;
    }

    LPVOID base_address = NULL;
    int result = allocate_executable_memory(payload_size, image_base, &base_address);
    if (result == -1)
    {
        fprintf(stderr, "[!] allocate_executable_memory() failed.\n");
        return 1;
    }
    else if (result == 1) 
    {
        // Relocation patching needs to occur

    }

    // printf("[+] Copying raw binary bytes into allocated memory region ...\n");
    // memcpy(base_address, payload, payload_size);

    printf("[+] Freeing allocated memory ...\n");
    if (!VirtualFree(base_address, (DWORD)payload_size, MEM_DECOMMIT))
    {
        fprintf(stderr, "[!] VirtualFree() failed.\n");
        return 1;
    }

    return 0;
}