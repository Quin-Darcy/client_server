#ifndef EXECUTION_H
#define EXECUTION_H

int parse_headers(const unsigned char* payload, DWORD* image_base, DWORD* address_of_entry);
int allocate_executable_memory(const size_t payload_size, const DWORD image_base, LPVOID* base_address);
void apply_relocations(const DWORD image_base, const LPVOID base_address);
int resolve_imports(const unsigned char* base_address);
// void execute_entry_point(LPVOID base_address);
int execute_payload(const unsigned const char* payload, size_t payload_size);

#endif