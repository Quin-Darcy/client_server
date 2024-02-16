#include <stdio.h>
#include "execution.h"

int test_execution()
{
    printf("Hello, World from execution.c!\n");
    return 0;
}

int execute_payload(const char* payload, size_t payload_size)
{
    return test_execution();
}