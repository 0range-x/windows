#include "buffer.h"

DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//ʹ��PE�ṹ�����ļ���С
	PIMAGE_SECTION_HEADER pTempSectionHeaderTo = pSectionHeader;
	for (DWORD i = 1; i < pPEHeader->NumberOfSections; i++)
		pTempSectionHeaderTo++;
	DWORD fileSize = pTempSectionHeaderTo->SizeOfRawData + pTempSectionHeaderTo->PointerToRawData;
	//����File��С�ռ�
	*pNewBuffer = (PDWORD)malloc(fileSize);
	if (!*pNewBuffer)
	{
		printf("[-] ����ImageBufferʧ�ܣ�");
		free(*pNewBuffer);
		return 0;
	}
	memset(*pNewBuffer, 0, fileSize);
	//����SizeOfHeaders
	memcpy(*pNewBuffer, pImageBuffer, pOptionHeader->SizeOfHeaders);
	//ѭ�������ڵ��ڴ������
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((void*)((DWORD)*pNewBuffer + pTempSectionHeader->PointerToRawData), (void*)((DWORD)pImageBuffer + pTempSectionHeader->VirtualAddress), pTempSectionHeader->SizeOfRawData);
		pTempSectionHeader++;
	}
	return fileSize;
}