#include <windows.h>
#include <stdio.h>

int main() 
{
    MessageBox(NULL, "Hello, World!", "Simple Message Box", MB_OK | MB_ICONINFORMATION);
    getchar();
    return 0;
}
