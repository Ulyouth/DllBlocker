/**************************************************************************************
** AUTHOR: Ulyouth (https://github.com/ulyouth)
** DATE: 22.04.2021
** DESC: The following code is an example on how to block certain DLLs from being
** forcibly loaded onto a process. It works for all DLLs loaded from usermode and by 
** many loaded by the kernel as well. The trick consists in creating a suspended 
** process, hooking the LdrLoadDll function while still suspended, and then resume 
** the process. It is an effective anti-debugging method, which also works against 
** many HIPS.
***************************************************************************************/

#include <stdio.h>
#include <Windows.h>
#include <Winternl.h>

typedef NTSTATUS(NTAPI *PLDRLOADDLL)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef NTSTATUS(NTAPI *PNTQRYINFOPROC)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

PLDRLOADDLL pLdrLoadDll = 0;

int tolower2(int c)
{
	return (c >= 'A' && c <= 'Z') ? (c + 32) : c;
}

int _memicmp2(const void *buf1, const void *buf2, size_t n)
{
	int f = 0, l = 0;
	const unsigned char *dst = buf1, *src = buf2;

	while (n-- && f == l) {
		f = tolower2(*dst++);
		l = tolower2(*src++);
	}

	return f - l;
}

size_t strlen2(const char *str)
{
	register const char *s;

	for (s = str; *s; s++);
	return s - str;
}

size_t wcslen2(const wchar_t *str)
{
	const wchar_t *p = str;

	while (*p)
		p++;

	return p - str;
}

__declspec(naked) NTSTATUS NTAPI CV_LdrLoadDll(PWCHAR PathToFile, PULONG Flags, 
	PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle)
{
	__asm {
		mov edi, edi;           // The "Stolen bytes" - I think those should be the
		push ebp;               // same in all 32-bits Windows versions, but I 
		mov ebp, esp;           // haven't checked to be sure.
		mov eax, pLdrLoadDll;   //  
		add eax, 0x05;          // 
		jmp eax;                // Resume the LdrLoadDll routine
	}
}

NTSTATUS NTAPI HK_LdrLoadDll(PWCHAR PathToFile, PULONG Flags, 
	PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle)
{
	/***************************************************************************
	** This function will be called during process startup and only ntdll might
	** be available at this point, so its unwise to call any kernel or even CRT
	** functions here inside.
	****************************************************************************/

	// Convert the length of the module's name from bytes to unicode characters
	DWORD dwModLen = ModuleFileName->Length / 2;

	// List of names to be blocked
	wchar_t *lpBlockList[] = { L"test1.dll", L"\x00"};

	for (int x = 0;; x++) {
		DWORD dwBlockLen = wcslen2(lpBlockList[x]);

		if (!dwBlockLen)
			break;

		// Block if the current name is found in the module's name or path
		for (DWORD y = 0; y <= (dwModLen - dwBlockLen); y++) {
			if (_memicmp2(&ModuleFileName->Buffer[y], lpBlockList[x], dwBlockLen * 2) == 0)
				return STATUS_DLL_NOT_FOUND;
		}
	}

	return CV_LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
}

LPVOID GetProcessBaseAddress(HANDLE hProcess)
{
	PNTQRYINFOPROC pNtQueryInformationProcess = (PNTQRYINFOPROC)GetProcAddress(
		GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");

	if (!pNtQueryInformationProcess)
		return 0;

	PROCESS_BASIC_INFORMATION Pbi = { 0 };
	NTSTATUS status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, 
		&Pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);

	if (status != 0)
		return 0;

	LPVOID lpImgBase = 0;
	DWORD dwRead;

	// Read the image base about the process's PEB
	if (!ReadProcessMemory(hProcess, &Pbi.PebBaseAddress->Reserved3[1], &lpImgBase, 
		sizeof(LPVOID), &dwRead))
		return 0;

	return lpImgBase;
}

BOOL ProtectNWriteMemory(HANDLE hProcess, LPVOID lpAddress, LPVOID lpBuffer, DWORD dwBufSize)
{
	DWORD dwOldProtect;
	return (
		VirtualProtectEx(hProcess, lpAddress, dwBufSize, PAGE_READWRITE, &dwOldProtect) &&
		WriteProcessMemory(hProcess, lpAddress, lpBuffer, dwBufSize, 0) &&
		VirtualProtectEx(hProcess, lpAddress, dwBufSize, dwOldProtect, &dwOldProtect)
		) ? TRUE : FALSE;
}

BOOL CreateProtectedProcess(LPCSTR lpExePath)
{
	BOOL bRes = FALSE;
	PROCESS_INFORMATION Pi = { 0 };
	STARTUPINFO Si = { 0 };

	Si.cb = sizeof(Si);

	// Create the process in suspended state
	if (!CreateProcess(lpExePath, 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &Si, &Pi))
		return FALSE;

	printf("\n\nNEW PID: %d", Pi.dwProcessId);
	
	// Get the base addresses of the current and the process to be protected
	LPVOID lpLocalBase = GetModuleHandle(0);
	LPVOID lpRemoteBase = GetProcessBaseAddress(Pi.hProcess);
	
	if (!lpRemoteBase)
		goto cleanup;

	printf("\nLOCAL BASE ADDRESS: 0x%.8X\nREMOTE BASE ADDRESS: 0x%.8X\nLdrLoadDll: 0x%.8X\n", 
		(UINT)lpLocalBase, (UINT)lpRemoteBase, (UINT)pLdrLoadDll);

	// Calculate the address of the remote hook & LdrLoadDll pointer
	LPVOID lpPtr = (LPVOID)((ULONG_PTR)lpRemoteBase +
		(ULONG_PTR)&pLdrLoadDll - (ULONG_PTR)lpLocalBase);
	LPVOID lpHook = (LPVOID)((ULONG_PTR)lpRemoteBase + 
		(ULONG_PTR)HK_LdrLoadDll - (ULONG_PTR)lpLocalBase);

	// Calculate the distance between the original address and the hook
	// ASM JMP SYNTAX: TO - FROM - 5
	DWORD dwDelta = (DWORD)((ULONG_PTR)lpHook - (ULONG_PTR)pLdrLoadDll - 5);

	// Prepare the detour
	BYTE lpJmp[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	*((DWORD_PTR *)&lpJmp[1]) = dwDelta;

	// Write the detour & LdrLoadDll pointer to the protected process
	if (!ProtectNWriteMemory(Pi.hProcess, lpPtr, &pLdrLoadDll, sizeof(LPVOID)) ||
		!ProtectNWriteMemory(Pi.hProcess, pLdrLoadDll, lpJmp, 5))
		goto cleanup;

	bRes = (ResumeThread(Pi.hThread)) ? TRUE : FALSE;

cleanup:
	if (Pi.hThread) CloseHandle(Pi.hThread);
	if (Pi.hProcess) {
		if (!bRes) TerminateProcess(Pi.hProcess, 0);
		CloseHandle(Pi.hProcess);
	}

	return bRes;
}

int main(int argc, char **argv)
{
	// The 'pLdrLoadDll' pointer is set by the parent process when protected
	BOOL bProtected = (pLdrLoadDll) ? TRUE : FALSE;
	printf("\nPROCESS STATUS: %s", (bProtected) ? "Protected" : "Not protected");

	if (!bProtected) {
		// Init the LdrLoadDll pointer
		pLdrLoadDll = (PLDRLOADDLL)GetProcAddress(GetModuleHandle("ntdll.dll"), "LdrLoadDll");	
		CreateProtectedProcess(argv[0]);
	}
		
	getchar();
}

