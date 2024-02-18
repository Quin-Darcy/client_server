#ifndef EXECUTION_H
#define EXECUTION_H

int parse_headers(const char* payload, DWORD* image_base, DWORD* address_of_entry);
int allocate_executable_memory(const size_t payload_size, const ULONG_PTR image_base, LPVOID* base_address);
// void execute_entry_point(LPVOID base_address);
int execute_payload(const char* payload, size_t payload_size);

#endif