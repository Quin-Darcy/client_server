#ifndef EXECUTION_H
#define EXECUTION_H

int parse_headers(const unsigned char* payload, DWORD* image_base, DWORD* address_of_entry);
int allocate_executable_memory(const size_t payload_size, const DWORD image_base, LPVOID* base_address);
int fix_relocations(unsigned char* payload, const size_t payload_size, const DWORD image_base, const LPVOID base_address);
// void execute_entry_point(LPVOID base_address);
int execute_payload(unsigned const char* payload, size_t payload_size);

#endif