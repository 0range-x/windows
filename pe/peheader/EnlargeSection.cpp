#include "buffer.h"

BOOL EnlargeSection(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer, size_t EnlargeSize) {
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

	//将节指针指向最后一个节
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		pSectionHeader++;
	}

	//申请一块新内存
	*pNewBuffer = (PDWORD)malloc(pOptionHeader->SizeOfImage + EnlargeSize);
	if (!*pNewBuffer) {
		printf("[-] 申请扩大节后的空间失败");
		free(*pNewBuffer);
		return false;
	}
	memset(*pNewBuffer, 0, pOptionHeader->SizeOfImage);
	memset(*pNewBuffer, (int)pImageBuffer, pOptionHeader->SizeOfImage);

	//将最后一个节的sizeofRawData 和VirtualSize 改成N
	//N = (SizeOfRawData 或者 VirtualSize 内存对齐后的值) + Ex
	pSectionHeader->SizeOfRawData = pSectionHeader->Misc.VirtualSize = Align((pSectionHeader->SizeOfRawData += EnlargeSize) > (pSectionHeader->Misc.VirtualSize += EnlargeSize) ?
		pSectionHeader->SizeOfRawData : pSectionHeader->Misc.VirtualSize, pOptionHeader->SectionAlignment);

	//修改sizeofimage大小
	pOptionHeader->SizeOfImage = Align(pOptionHeader->SizeOfImage, pOptionHeader->SectionAlignment);

	return true;
}

