#include "APIresolve.h"

uint64_t custom(void)
{
    int hash_MessageBoxA = 0x384f14b4;
    uint64_t messageboxa_ptr = 0x00;

    typedef BOOL(WINAPI* MESSAGEBOXA)(uint64_t, LPCSTR, LPCSTR, uint64_t);

    messageboxa_ptr = getFunctionPtr(HASH_user32, hash_MessageBoxA);
    if (messageboxa_ptr == 0x00)
    {
        return 1;
    }
    char titlestring[] = { 'h','i',0x00 };
    ((MESSAGEBOXA)messageboxa_ptr)(NULL,titlestring,NULL,0);
	

	return 0;
}