#include "buffer.h"

BOOL AddFileBufferToSectionTable(IN LPVOID pFileBuffer, OUT LPVOID* pNewBuffer, IN const char* sectionTable, IN size_t SectionTableSize) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 0x4);	
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	DWORD whiteSpaceSize = 0;

	//判断空间是否足够,可以添加一个表
	//判断条件
	//sizeofHeader - （DOS + 垃圾数据 + PE标记 + 标准PE头 + 可选PE头 + 已存在节表）>= 2个节表的大小
	whiteSpaceSize = pOptionHeader->SizeOfHeaders - (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader) + ((pPEHeader->NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER));
	if (whiteSpaceSize < sizeof(IMAGE_SECTION_HEADER)) {
		printf("[-] 数据缓冲区太小无法添加节表.");
		return false;
	}

	//copy 一个新的节表
	char* pTmpFile = (char*)pFileBuffer;
	char* pTmpFileCopy = (char*)pFileBuffer;
	//第一个节表开始的地方
	pTmpFile = pTmpFile + (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader);
	//最后一个节表的结尾
	pTmpFileCopy = pTmpFileCopy + (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader + ((pPEHeader->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER)));
	memcpy(pTmpFileCopy, pTmpFile, sizeof(IMAGE_SECTION_HEADER));

	//修改pe中节的数量
	pPEHeader->NumberOfSections += 1;
	//修改sizeofImage大小
	pOptionHeader->SizeOfImage += SectionTableSize;
	
	//在原有数据最后，新增一个节的数据(内存对齐的整数倍)
	//使用PE结构计算文件大小
	PIMAGE_SECTION_HEADER pTempSectionHeaderTo = pSectionHeader;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
		pTempSectionHeaderTo++;
	
	DWORD fileSize = pTempSectionHeaderTo->SizeOfRawData + pTempSectionHeaderTo->PointerToRawData;
	//申请file空间大小
	*pNewBuffer = (PDWORD)malloc(fileSize + SectionTableSize);
	if (!pNewBuffer) {
		printf("申请ImageBuffer失败");
		free(*pNewBuffer);
		return false;
	}

	memset(*pNewBuffer, 0, fileSize + SectionTableSize);
	//修正节表属性
	PIMAGE_SECTION_HEADER pTempSectionHeaderTo2 = (PIMAGE_SECTION_HEADER)pTmpFileCopy;

	memcpy(pTempSectionHeaderTo2->Name, sectionTable, 4);
	pTempSectionHeaderTo2->Misc.VirtualSize = SectionTableSize;
	pTempSectionHeaderTo2->VirtualAddress = pTempSectionHeaderTo->VirtualAddress + Align(pTempSectionHeaderTo->Misc.VirtualSize, pOptionHeader->SectionAlignment);
	pTempSectionHeaderTo2->SizeOfRawData = Align(SectionTableSize, pOptionHeader->FileAlignment);
	pTempSectionHeaderTo2->PointerToRawData = pTempSectionHeaderTo->PointerToRawData + Align(pTempSectionHeaderTo->SizeOfRawData,pOptionHeader->FileAlignment);
	memcpy(*pNewBuffer, pFileBuffer, fileSize);
	return true;

}



DWORD Align(DWORD size, DWORD ALIGN_BASE) {
	assert(0 != ALIGN_BASE);
	if (size % ALIGN_BASE)
		size = (size / ALIGN_BASE + 1) * ALIGN_BASE;
	return size;
}