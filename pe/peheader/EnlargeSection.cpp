#include "buffer.h"

BOOL EnlargeSection(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer, size_t EnlargeSize) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	
	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("MZ�ļ���־ͷ�����ڣ�");
		free(pImageBuffer);
		return false;
	}

	//����ָ��ָ�����һ����
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		pSectionHeader++;
	}

	//����һ�����ڴ�
	*pNewBuffer = (PDWORD)malloc(pOptionHeader->SizeOfImage + EnlargeSize);
	if (!*pNewBuffer) {
		printf("[-] ��������ں�Ŀռ�ʧ��");
		free(*pNewBuffer);
		return false;
	}
	memset(*pNewBuffer, 0, pOptionHeader->SizeOfImage);
	memset(*pNewBuffer, (int)pImageBuffer, pOptionHeader->SizeOfImage);

	//�����һ���ڵ�sizeofRawData ��VirtualSize �ĳ�N
	//N = (SizeOfRawData ���� VirtualSize �ڴ������ֵ) + Ex
	pSectionHeader->SizeOfRawData = pSectionHeader->Misc.VirtualSize = Align((pSectionHeader->SizeOfRawData += EnlargeSize) > (pSectionHeader->Misc.VirtualSize += EnlargeSize) ?
		pSectionHeader->SizeOfRawData : pSectionHeader->Misc.VirtualSize, pOptionHeader->SectionAlignment);

	//�޸�sizeofimage��С
	pOptionHeader->SizeOfImage = Align(pOptionHeader->SizeOfImage, pOptionHeader->SectionAlignment);

	return true;
}

