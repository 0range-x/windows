#include "buffer.h"

BOOL MergingSection(IN OUT LPVOID* pImageBuffer) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("MZ文件标志头不存在！");
		free(pImageBuffer);
		return false;
	}

	DWORD nax = pSectionHeader->SizeOfRawData > pSectionHeader->Misc.VirtualSize ? pSectionHeader->SizeOfRawData : pSectionHeader->Misc.VirtualSize;
	PIMAGE_SECTION_HEADER pSectionHeader_tmp = pSectionHeader;
	pSectionHeader_tmp += (pPEHeader->NumberOfSections - 1);
	pSectionHeader->SizeOfRawData = pSectionHeader->Misc.VirtualSize = Align(pSectionHeader_tmp->VirtualAddress + max - pOptionHeader->SizeOfHeaders, pOptionHeader->SectionAlignment);
	pPEHeader->NumberOfSections = 1;
	return true;
}	