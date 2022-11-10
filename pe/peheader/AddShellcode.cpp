#define _CRT_SECURE_NO_WARNINGS

#include<Windows.h>
#include<stdlib.h>
#include <cstdio>

#define FILEPATH_IN "E:\\pe.exe"
#define FILEPATH_OUT "E:\\ca.exe"
#define MESSAGEBOXADDR 0x755e0660
#define SHELLCODELENGTH 0x12		//添加代码长度

BYTE shellCode[] = {
	0x6A,0x00,0x6A,0x00,0x6A,0x00,0x6A,0x00,
	0xE8,0x00,0x00,0x00,0x00,
	0xE9,0x00,0x00,0x00,0x00
};

int FileLength(FILE* fp) {
	int fileSize = 0;
	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);   //指针归位
	return fileSize;
}

DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer) {
	FILE* pFile = NULL;
	DWORD fileSize = 0;
	//pFileBuffer = NULL;

	//打开文件
	pFile = fopen(lpszFile, "rb+");
	if (!pFile) {
		printf("[-] Open file Error.\n");
		return NULL;
	}

	//读取文件大小
	fileSize = FileLength(pFile);

	//分配缓冲区
	*pFileBuffer = malloc(fileSize);
	if (!pFileBuffer) {
		printf("[-] Malloc to pFileBuffer failed.\n");
		fclose(pFile);
		return NULL;
	}

	//将文件数据读取到缓冲区
	size_t n = fread(*pFileBuffer, fileSize, 1, pFile);
	if (!n) {
		printf("[-] Failed to fread.\n");
		free(*pFileBuffer);
		fclose(pFile);
		return NULL;
	}
	fclose(pFile);
	return fileSize;
}

void addShellcode() {
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD RVA_codeBegin = 0;

	size_t size = ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pFileHeader->SizeOfOptionalHeader);

	//代码空白区（文件对齐后-文件对齐前） 存不下shellcode的长度
	if ((pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize) < SHELLCODELENGTH) {
		printf("[-] Space in code is not enough.");
		free(pFileBuffer);
		exit(0);
	}
	//添加shellcode代码
	//codeBegin = 空白区的起始地址 = shellcode在文件中的起始地址
	PBYTE codeBegin = (PBYTE)((DWORD)pFileBuffer + pSectionHeader->PointerToRawData + pSectionHeader->Misc.VirtualSize + 8);
	printf("[+] codeBegin: %x\n", codeBegin);
	//拷贝shellcode到空白区
	memcpy(codeBegin, shellCode, SHELLCODELENGTH);

	//FOA -> RVA
	//Foa_shellcodeAddr - PointerToRawData + VirtualAddress + ImageBase = Rva_shellcodeAddr
	if (pOptionHeader->FileAlignment != pOptionHeader->SectionAlignment) {
		//imagebuffer 中 - 文件偏移- imagebuffer = 在imagebuffer中的偏移  
		RVA_codeBegin = (DWORD)codeBegin - pSectionHeader->PointerToRawData - (DWORD)pFileBuffer + pSectionHeader->VirtualAddress + pOptionHeader->ImageBase ;
	}
	else
	{
		RVA_codeBegin = (DWORD)codeBegin - (DWORD)pFileBuffer;
	}

	//修正e8
	// rva_codebegin = 6a 00 在内存中的地址
	//e8后的地址 = shellcode的地址 - e8 的下一条指令的地址 ,算的是运行时的地址，不是ImageBuffer里的地址，相差了imagebase
	//D = 8(messagebox的长度) + 5(e8指令长度) 

	DWORD callAddr = MESSAGEBOXADDR - (RVA_codeBegin + 0xD);
	
	printf("[+] callAddr: %x\n", callAddr);
	*(PDWORD)(codeBegin + 0x9) = callAddr;    //修改e8后面的硬编码，从第9个字节开始

	//修正e9
	//e9后的地址 = Imagebase + AddressEntryPoint - e9的下一条指令的地址
	 DWORD jmpAddr = (pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (RVA_codeBegin + 0x12);
	 printf("[+] ImageBase: %x\n[+] AddressEntrypoint: %x\n", pOptionHeader->ImageBase, pOptionHeader->AddressOfEntryPoint);
	*(PDWORD)(codeBegin + 0xE) = jmpAddr;		//修改e9后面的硬编码
	printf("[+] jmpAddr:%x\n", jmpAddr);

	//修正OEP
	//OEP = RVA_shellcode -imagebase
	pOptionHeader->AddressOfEntryPoint = RVA_codeBegin - pOptionHeader->ImageBase;
	
	printf("[+] OEP:%x\n",  RVA_codeBegin - pOptionHeader->ImageBase);

	//存入文件
	FILE* fp = fopen(FILEPATH_OUT,"wb+");
	fwrite(pFileBuffer, size, 1, fp);
	fclose(fp);

}

int main(int argc, char* argv[]) {
	addShellcode();
	return 0;
}