#include <windows.h>
#include "APIresolve.h"
// include callstack_evade.h if you want to use call stack evasion
#include "callstack_evade.h"

extern "C" uint64_t custom(void)
{
    //Must init this reference to the hidecallstack module
    extern VOID CALLBACK hidecallstack(PTP_CALLBACK_INSTANCE Instance, LPVOID Context, PTP_WORK Work);

    // local vars
    int hash_MessageBoxA = 0x384f14b4;
    uint64_t messageboxa_ptr = 0x00;
    int hash_NtAllocateVirtualMemory = 0x6793c34c;
    uint64_t ntallocatevirtualmemory_ptr = 0x00;
    int hash_memcpy_s = 0x77f62642;
    uint64_t memcpy_s_ptr = 0x00;
    LPVOID allocatedAddress = NULL;
    SIZE_T allocatedsize = 0x1000;

    // define WINAPI functions
    typedef BOOL(WINAPI* MESSAGEBOXA)(uint64_t, LPCSTR, LPCSTR, uint64_t);
    typedef INT(WINAPI* MEMCPY_S)(LPVOID, SIZE_T, LPVOID, SIZE_T);

    // Resolve WINAPI functions
    ntallocatevirtualmemory_ptr = getFunctionPtr(HASH_ntdll, hash_NtAllocateVirtualMemory);
    if (ntallocatevirtualmemory_ptr == 0x00)
    {
        return 1;
    }
    memcpy_s_ptr = getFunctionPtr(HASH_ntdll, hash_memcpy_s);
	if (memcpy_s_ptr == 0x00)
	{
		return 1;
	}
    messageboxa_ptr = getFunctionPtr(HASH_user32, hash_MessageBoxA);
    if (messageboxa_ptr == 0x00)
    {
        return 1;
    }

    // Build a structure with the function you want to call and its args to pass to TpAllocWork for CALLBACK
    typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
        UINT_PTR pNtAllocateVirtualMemory;   // pointer to NtAllocateVirtualMemory - rax
        HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
        PVOID* address;                      // PVOID *BaseAddress - rdx; ULONG_PTR ZeroBits - 0 - r8
        PSIZE_T size;                        // PSIZE_T RegionSize - r9; ULONG AllocationType - MEM_RESERVE|MEM_COMMIT = 3000 - stack pointer
        ULONG permissions;                   // ULONG Protect - PAGE_EXECUTE_READ - 0x20 - stack pointer
    } NTALLOCATEVIRTUALMEMORY_ARGS, *PNTALLOCATEVIRTUALMEMORY_ARGS;
    // Set values in struct
    NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryArgs = { 0 };
    ntAllocateVirtualMemoryArgs.pNtAllocateVirtualMemory = ntallocatevirtualmemory_ptr;
    ntAllocateVirtualMemoryArgs.hProcess = (HANDLE)-1;
    ntAllocateVirtualMemoryArgs.address = &allocatedAddress;
    ntAllocateVirtualMemoryArgs.size = &allocatedsize;
    ntAllocateVirtualMemoryArgs.permissions = PAGE_EXECUTE_READWRITE;

    // Pass your struct and a ptr to hidecallstack into CallStackEvasion()
    CallStackEvasion(&ntAllocateVirtualMemoryArgs, (PTP_WORK_CALLBACK)hidecallstack);

    // Bonus memes
    char titlestring[] = { 'h','i',0x00 };
    ((MEMCPY_S)memcpy_s_ptr)((LPVOID)allocatedAddress, allocatedsize, titlestring, sizeof(titlestring));
    ((MESSAGEBOXA)messageboxa_ptr)(NULL,(LPCSTR)allocatedAddress,NULL,0);
  
	return 0;
}
