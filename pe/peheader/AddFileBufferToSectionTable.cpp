#include "buffer.h"

BOOL AddFileBufferToSectionTable(IN LPVOID pFileBuffer, OUT LPVOID* pNewBuffer, IN const char* sectionTable, IN size_t SectionTableSize) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 0x4);	
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	DWORD whiteSpaceSize = 0;

	//�жϿռ��Ƿ��㹻,�������һ����
	//�ж�����
	//sizeofHeader - ��DOS + �������� + PE��� + ��׼PEͷ + ��ѡPEͷ + �Ѵ��ڽڱ�>= 2���ڱ�Ĵ�С
	whiteSpaceSize = pOptionHeader->SizeOfHeaders - (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader) + ((pPEHeader->NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER));
	if (whiteSpaceSize < sizeof(IMAGE_SECTION_HEADER)) {
		printf("[-] ���ݻ�����̫С�޷���ӽڱ�.");
		return false;
	}

	//copy һ���µĽڱ�
	char* pTmpFile = (char*)pFileBuffer;
	char* pTmpFileCopy = (char*)pFileBuffer;
	//��һ���ڱ�ʼ�ĵط�
	pTmpFile = pTmpFile + (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader);
	//���һ���ڱ�Ľ�β
	pTmpFileCopy = pTmpFileCopy + (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader + ((pPEHeader->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER)));
	memcpy(pTmpFileCopy, pTmpFile, sizeof(IMAGE_SECTION_HEADER));

	//�޸�pe�нڵ�����
	pPEHeader->NumberOfSections += 1;
	//�޸�sizeofImage��С
	pOptionHeader->SizeOfImage += SectionTableSize;
	
	//��ԭ�������������һ���ڵ�����(�ڴ�����������)
	//ʹ��PE�ṹ�����ļ���С
	PIMAGE_SECTION_HEADER pTempSectionHeaderTo = pSectionHeader;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
		pTempSectionHeaderTo++;
	
	DWORD fileSize = pTempSectionHeaderTo->SizeOfRawData + pTempSectionHeaderTo->PointerToRawData;
	//����file�ռ��С
	*pNewBuffer = (PDWORD)malloc(fileSize + SectionTableSize);
	if (!pNewBuffer) {
		printf("����ImageBufferʧ��");
		free(*pNewBuffer);
		return false;
	}

	memset(*pNewBuffer, 0, fileSize + SectionTableSize);
	//�����ڱ�����
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