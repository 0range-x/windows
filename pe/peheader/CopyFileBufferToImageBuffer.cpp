#include"buffer.h"

//����ImageBuffer�Ĵ�С
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer)
{
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] MZ�ļ���־ͷ�����ڣ�");
		free(pFileBuffer);
		return 0;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//����Image��С�ռ�
	*pImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if (!*pImageBuffer)
	{
		printf("����ImageBufferʧ�ܣ�");
		free(*pImageBuffer);
		return 0;
	}
	memset(*pImageBuffer, 0, pOptionHeader->SizeOfImage);
	//����SizeOfHeaders
	memcpy(*pImageBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);
	//ѭ�������ڵ��ڴ������
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((void*)((DWORD)*pImageBuffer + pTempSectionHeader->VirtualAddress), (void*)((DWORD)pFileBuffer + pTempSectionHeader->PointerToRawData), pTempSectionHeader->SizeOfRawData);
		pTempSectionHeader++;
	}
	return pOptionHeader->SizeOfImage;
}