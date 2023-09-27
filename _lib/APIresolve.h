#pragma once
#include <windows.h>
#include <stdint.h>
#include "ntdll.h"

#define HASH_kernel32 0x7040ee75
#define HASH_ntdll 0x22d3b5ed
#define HASH_user32 0x5a6bd3f3
#define HASH_LoadLibraryA 0x5fbff0fb
#define HASH_VirtualProtect 0x844ff18d 

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef BOOL(WINAPI* VIRTUALPROTECT)(uint64_t, SIZE_T, DWORD, PDWORD);

static int
djb2(unsigned char* str)
{
	unsigned long hash = 5381;
	int c;

	while ((c = *str++))
		hash = ((hash << 5) + hash) + c;

	return hash;
}

static int
unicode_djb2(const wchar_t* str)
{

	int hash = 5381;
	DWORD val;

	while (*str != 0) {
		val = (DWORD)*str++;
		hash = ((hash << 5) + hash) + val;
	}

	return hash;

}

static WCHAR* 
toLower(WCHAR *str)
{

	WCHAR* start = str;

	while (*str) {

		if (*str <= L'Z' && *str >= 'A') {
			*str += 32;
		}

		str += 1;

	}

	return start;

}

static uint64_t getDllBase(int dll_hash)
{
   _PPEB ptr_peb = NULL;
	PPEB_LDR_DATA ptr_ldr_data = NULL;
	PLDR_DATA_TABLE_ENTRY ptr_module_entry = NULL, ptr_start_module = NULL;
	PUNICODE_STR dll_name = NULL;

	ptr_peb = (_PEB*)__readgsqword(0x60);
	ptr_ldr_data = ptr_peb->pLdr;
	ptr_module_entry = ptr_start_module = (PLDR_DATA_TABLE_ENTRY)ptr_ldr_data->InMemoryOrderModuleList.Flink;

	do{

		dll_name = &ptr_module_entry->BaseDllName;

		if (dll_name->pBuffer == NULL)
			return 0;

		if (unicode_djb2(toLower(dll_name->pBuffer)) == dll_hash)
			return (uint64_t)ptr_module_entry->DllBase;

		ptr_module_entry = (PLDR_DATA_TABLE_ENTRY)ptr_module_entry->InMemoryOrderModuleList.Flink;

	} while (ptr_module_entry != ptr_start_module);
    return 0;
}

static uint64_t 
parseHdrForPtr(uint64_t dll_base, int function_hash) {

	PIMAGE_NT_HEADERS nt_hdrs = NULL;
	PIMAGE_DATA_DIRECTORY data_dir= NULL;
	PIMAGE_EXPORT_DIRECTORY export_dir= NULL;

	uint32_t* ptr_exportadrtable = 0x00;
	uint32_t* ptr_namepointertable = 0x00;
	uint16_t* ptr_ordinaltable = 0x00;

	uint32_t idx_functions = 0x00;

	unsigned char* ptr_function_name = NULL;


	nt_hdrs = (PIMAGE_NT_HEADERS)(dll_base + (uint64_t)((PIMAGE_DOS_HEADER)(size_t)dll_base)->e_lfanew);
	data_dir = (PIMAGE_DATA_DIRECTORY)&nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	export_dir = (PIMAGE_EXPORT_DIRECTORY)(dll_base + (uint64_t)data_dir->VirtualAddress);

	ptr_exportadrtable = (uint32_t*)(dll_base + (uint64_t)export_dir->AddressOfFunctions);
	ptr_namepointertable = (uint32_t*)(dll_base + (uint64_t)export_dir->AddressOfNames);
	ptr_ordinaltable = (uint16_t*)(dll_base + (uint64_t)export_dir->AddressOfNameOrdinals);

	for(idx_functions = 0; idx_functions < export_dir->NumberOfNames; idx_functions++){

		ptr_function_name = (unsigned char*)dll_base + (ptr_namepointertable[idx_functions]);
		if (djb2(ptr_function_name) == function_hash) {
			WORD nameord = ptr_ordinaltable[idx_functions];
			DWORD rva = ptr_exportadrtable[nameord];
			return dll_base + rva;
		}

	}

	return 0;
}


static uint64_t loadDll(int crypted_dll_hash) {

	uint64_t kernel32_base = 0x00;
	uint64_t fptr_loadLibary = 0x00;
	uint64_t ptr_loaded_dll = 0x00;

	kernel32_base = getDllBase(HASH_kernel32);
	if (kernel32_base == 0x00) {
		return 0;
	}
	// Logic to call LoadLibrary on non-loaded modules - should probably just force user to resolve and call loadlibrary in custom code rather than handle it here. idk
	fptr_loadLibary = parseHdrForPtr(kernel32_base, HASH_LoadLibraryA);
	if (fptr_loadLibary == 0x00) {
		return 0;
	}
	if (crypted_dll_hash == HASH_user32) {
		char dll_name[] = { 'u', 's', 'e', 'r', '3' ,'2' ,'.', 'd', 'l', 'l', 0x00 };
		ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
	} 

	return ptr_loaded_dll;

}

static uint64_t 
getFunctionPtr(int dll_hash, int function_hash) {

	uint64_t dll_base = 0x00;
	uint64_t ptr_function = 0x00;

	dll_base = getDllBase(dll_hash);
	if (dll_base == 0) {
		dll_base = loadDll(dll_hash);
		if (dll_base == 0)
			return 0;
	}

	ptr_function = parseHdrForPtr(dll_base, function_hash);

	return ptr_function;
}
