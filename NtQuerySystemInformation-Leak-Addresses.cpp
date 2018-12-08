#include <Windows.h>
#include <stdio.h>

typedef struct SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	BYTE                 Name[255];
}SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11,
	SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                   SystemInformation,
	IN ULONG                    SystemInformationLength,
	OUT PULONG                  ReturnLength
	);

int wmain(int argc, WCHAR *argv[])
{

	HMODULE ntdll;
	HMODULE userBase;
	LPCWSTR lpModuleName = L"ntdll";
	LPCSTR lpProcName = "NtQuerySystemInformation";
	LPCSTR lpProcName2 = "HalDispatchTable";
	ULONG length = 0;
	PVOID kImageBase;
	PVOID pUserHAL;
	PVOID pKernelHAL;
	PCHAR kImageName;
	PSYSTEM_MODULE_INFORMATION pModuleInfo;

	ntdll = GetModuleHandle(lpModuleName);

	if (ntdll == INVALID_HANDLE_VALUE) {

		wprintf(L"[-]Error getting ntdll module handle...\r\n");

	}

	else {

		wprintf(L"[+]Returned ntdll module handle successfully...\r\n");

	}

	PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, lpProcName);

	if (NtQuerySystemInformation == NULL) {

		wprintf(L"[-]Error getting NtQuerySystemInformation process address...\r\n");

	}

	else {

		wprintf(L"[+]NtQuerySystemInformation address returned successfully...\r\n");

	}

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &length);

	if (length == 0) {

		wprintf(L"[-]Error calling NtQuerySystemInformation function...\r\n");

	}

	else {

		wprintf(L"[+]NtQuerySystemInformation function called successfully...\r\n");

	}

	pModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (pModuleInfo == NULL) {

		wprintf(L"[-]Error allocating memory for Module Information...\r\n");

	}

	else {

		wprintf(L"[+]Memory for Module Information allocated successfully...\r\n");

	}

	NtQuerySystemInformation(SystemModuleInformation, pModuleInfo, length, &length);

	kImageBase = (PVOID)pModuleInfo->Modules[0].ImageBaseAddress;
	kImageName = (PCHAR)pModuleInfo->Modules[0].Name;
	kImageName = (PCHAR)strrchr(kImageName, '\\') + 1;



	printf("[*]Kernel image base address: 0x%x\r\n", kImageBase);
	printf("[*]Kernel image name: %s\r\n", kImageName);

	userBase = LoadLibraryA(kImageName);


	if (userBase == INVALID_HANDLE_VALUE) {

		printf("[-]Error loading %s library...\r\n", kImageName);

	}

	else {

		printf("[+]%s library loaded successfully...\r\n", kImageName);

	}

	printf("[*]User base address: 0x%x\r\n", userBase);

	pUserHAL = (PVOID)GetProcAddress(userBase, lpProcName2);

	if (pUserHAL == NULL) {

		wprintf(L"[-]Error loading HalDispatchTable address...\r\n");

	}

	else {

		wprintf(L"[+]HalDispatchTable address loaded successfully...\r\n");

	}

	printf("[*]HAL Dispatch Table address: 0x%x\r\n", pUserHAL);

	wprintf(L"[*]Calculating address for HAL Dispatch Table in Kernel...\r\n");

	pKernelHAL = (PVOID)(((ULONG)pUserHAL - (ULONG)userBase) + (ULONG)kImageBase);

	printf("[*]HAL Dispatch Table offset is: 0x%x\r\n", (ULONG)pUserHAL - (ULONG)userBase);

	printf("[*]HAL Dispatch Table address in kernel is : 0x%x\r\n", pKernelHAL);

	system("PAUSE");

	return 0;
}