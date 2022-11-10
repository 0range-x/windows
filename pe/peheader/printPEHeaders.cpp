#include "buffer.h"

void PrintPEHeaders(LPVOID* pFileBuffer)
{
	if (*((PWORD)*pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("MZ文件标志头不存在！");
		free(*pFileBuffer);
		return;
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)*pFileBuffer;
	printf("**********DOS头**********\n");
	printf("[+]MZ标记-e_magic：%x\n", pDosHeader->e_magic);
	printf("[+]PE文件偏移-e_lfanew：%x\n", pDosHeader->e_lfanew);
	if (*((PDWORD)((DWORD)*pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("[-]NT文件标标记不存在！");
		free(*pFileBuffer);
		return;
	}
	//NT头
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)*pFileBuffer + pDosHeader->e_lfanew);
	printf("**********NT头**********\n");
	printf("[+]NT头-Signature：%x\n", pNTHeader->Signature);
	//标准PE头
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	printf("**********标准PE头**********\n");
	//printf("程序运行支持CPU型号：%x\n", pPEHeader->Machine);
	printf("[+]文件节数-NumberOfSections：%x\n", pPEHeader->NumberOfSections);
	printf("[+]可选PE头大小-SizeOfOptionalHeader：%x\n", pPEHeader->SizeOfOptionalHeader);
	//可选PE头
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	printf("**********可选PE头**********\n");
	printf("说明文件类型：%x\n", pOptionHeader->Magic);
	printf("[+]程序文件入口类型-AddressOfEntryPoint：%x\n", pOptionHeader->AddressOfEntryPoint);
	printf("[+]内存镜像基址-ImageBase：%x\n", pOptionHeader->ImageBase);
	printf("[+]内存对齐-SectionAlignment：%x\n", pOptionHeader->SectionAlignment);
	printf("[+]文件对齐-FileAlignment：%x\n", pOptionHeader->FileAlignment);
	printf("[+]内存PE文件映射尺寸-SizeOfImage：%x\n", pOptionHeader->SizeOfImage);
	printf("[+]头和节表文件对其后大小-SizeOfHeaders：%x\n", pOptionHeader->SizeOfHeaders);
	

	//节表解析
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	printf("\n");
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		printf("节表计数: %d\n", i);
		printf("[+]Name: %s\n", pSectionHeader->Name);
		printf("[+]没有对齐前的真实尺寸-VirtualSize: %x\n", pSectionHeader->Misc.VirtualSize);
		printf("[+]节区在内存中的偏移地址-VirtualAddress: %x\n", pSectionHeader->VirtualAddress);
		printf("[+]节在文件中对齐后的尺寸-SizeOfRawData: %x\n", pSectionHeader->SizeOfRawData);
		printf("[+]节区在文件中的偏移-PointerToRawData: %x\n", pSectionHeader->PointerToRawData);
		//printf("节的属性: %x\n", pSectionHeader->Characteristics);
		printf("\n");
		pSectionHeader++;
	}
	free(*pFileBuffer);
}