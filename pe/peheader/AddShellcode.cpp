#define _CRT_SECURE_NO_WARNINGS

#include<Windows.h>
#include<stdlib.h>
#include <cstdio>

#define FILEPATH_IN "E:\\pe.exe"
#define FILEPATH_OUT "E:\\ca.exe"
#define MESSAGEBOXADDR 0x755e0660
#define SHELLCODELENGTH 0x12		//��Ӵ��볤��

BYTE shellCode[] = {
	0x6A,0x00,0x6A,0x00,0x6A,0x00,0x6A,0x00,
	0xE8,0x00,0x00,0x00,0x00,
	0xE9,0x00,0x00,0x00,0x00
};

int FileLength(FILE* fp) {
	int fileSize = 0;
	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);   //ָ���λ
	return fileSize;
}

DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer) {
	FILE* pFile = NULL;
	DWORD fileSize = 0;
	//pFileBuffer = NULL;

	//���ļ�
	pFile = fopen(lpszFile, "rb+");
	if (!pFile) {
		printf("[-] Open file Error.\n");
		return NULL;
	}

	//��ȡ�ļ���С
	fileSize = FileLength(pFile);

	//���仺����
	*pFileBuffer = malloc(fileSize);
	if (!pFileBuffer) {
		printf("[-] Malloc to pFileBuffer failed.\n");
		fclose(pFile);
		return NULL;
	}

	//���ļ����ݶ�ȡ��������
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

	//����հ������ļ������-�ļ�����ǰ�� �治��shellcode�ĳ���
	if ((pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize) < SHELLCODELENGTH) {
		printf("[-] Space in code is not enough.");
		free(pFileBuffer);
		exit(0);
	}
	//���shellcode����
	//codeBegin = �հ�������ʼ��ַ = shellcode���ļ��е���ʼ��ַ
	PBYTE codeBegin = (PBYTE)((DWORD)pFileBuffer + pSectionHeader->PointerToRawData + pSectionHeader->Misc.VirtualSize + 8);
	printf("[+] codeBegin: %x\n", codeBegin);
	//����shellcode���հ���
	memcpy(codeBegin, shellCode, SHELLCODELENGTH);

	//FOA -> RVA
	//Foa_shellcodeAddr - PointerToRawData + VirtualAddress + ImageBase = Rva_shellcodeAddr
	if (pOptionHeader->FileAlignment != pOptionHeader->SectionAlignment) {
		//imagebuffer �� - �ļ�ƫ��- imagebuffer = ��imagebuffer�е�ƫ��  
		RVA_codeBegin = (DWORD)codeBegin - pSectionHeader->PointerToRawData - (DWORD)pFileBuffer + pSectionHeader->VirtualAddress + pOptionHeader->ImageBase ;
	}
	else
	{
		RVA_codeBegin = (DWORD)codeBegin - (DWORD)pFileBuffer;
	}

	//����e8
	// rva_codebegin = 6a 00 ���ڴ��еĵ�ַ
	//e8��ĵ�ַ = shellcode�ĵ�ַ - e8 ����һ��ָ��ĵ�ַ ,���������ʱ�ĵ�ַ������ImageBuffer��ĵ�ַ�������imagebase
	//D = 8(messagebox�ĳ���) + 5(e8ָ���) 

	DWORD callAddr = MESSAGEBOXADDR - (RVA_codeBegin + 0xD);
	
	printf("[+] callAddr: %x\n", callAddr);
	*(PDWORD)(codeBegin + 0x9) = callAddr;    //�޸�e8�����Ӳ���룬�ӵ�9���ֽڿ�ʼ

	//����e9
	//e9��ĵ�ַ = Imagebase + AddressEntryPoint - e9����һ��ָ��ĵ�ַ
	 DWORD jmpAddr = (pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (RVA_codeBegin + 0x12);
	 printf("[+] ImageBase: %x\n[+] AddressEntrypoint: %x\n", pOptionHeader->ImageBase, pOptionHeader->AddressOfEntryPoint);
	*(PDWORD)(codeBegin + 0xE) = jmpAddr;		//�޸�e9�����Ӳ����
	printf("[+] jmpAddr:%x\n", jmpAddr);

	//����OEP
	//OEP = RVA_shellcode -imagebase
	pOptionHeader->AddressOfEntryPoint = RVA_codeBegin - pOptionHeader->ImageBase;
	
	printf("[+] OEP:%x\n",  RVA_codeBegin - pOptionHeader->ImageBase);

	//�����ļ�
	FILE* fp = fopen(FILEPATH_OUT,"wb+");
	fwrite(pFileBuffer, size, 1, fp);
	fclose(fp);

}

int main(int argc, char* argv[]) {
	addShellcode();
	return 0;
}