#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <winnt.h>
#include "execution.h"

typedef struct 
{
    uint16_t e_magic;
    uint32_t e_lfanew;
} 
DOSHeader;


// Parse the PE bytes to obtain the ImageBase and AddressOfEntry
int parse_headers(const char* payload, DWORD* image_base, DWORD* address_of_entry_point)
{
    printf("[+] Parsing PE headers ...\n");

    DOSHeader *dos_header = (DOSHeader*)payload;

    if (dos_header->e_magic != 0x5A4D)
    {
        fprintf(stderr, "[!] Invalid PE file.\n");
        return 1;
    }

    DWORD nt_header_offset = dos_header->e_lfanew;
    printf("[i] NT Headers begin at offset: 0x%X\n", nt_header_offset);

    

    return 0;
}

// Requests block of memory suitable for code execution from OS
int allocate_executable_memory(const size_t payload_size, LPVOID* base_address)
{
    printf("[+] Allocating memory for the payload ...\n");

    *base_address = VirtualAlloc(NULL, (DWORD)payload_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (*base_address == NULL)
    {
        fprintf(stderr, "[!] VirtualAlloc() failed.\n");
        return 1;
    }

    return 0;
}

// Initiates execution of the in-memory binary by jumping to its entry point
// void execute_entry_point(LPVOID base_address)
// {

// }

int execute_payload(const char* payload, const size_t payload_size)
{
    LPVOID base_address = NULL;
    if (allocate_executable_memory(payload_size, &base_address) != 0)
    {
        fprintf(stderr, "[!] allocate_executable_memory() failed.\n");
        return 1;
    }

    printf("[+] Copying raw binary bytes into allocated memory region ...\n");
    memcpy(base_address, payload, payload_size);

    if (parse_headers(base_address) != 0)
    {
        fprintf(stderr, "[!] parse_headers() failed.\n");
        return 1;
    }

    printf("[+] Freeing allocated memory ...\n");
    if (!VirtualFree(base_address, (DWORD)payload_size, MEM_DECOMMIT))
    {
        fprintf(stderr, "[!] VirtualFree() failed.\n");
        return 1;
    }

    return 0;
}