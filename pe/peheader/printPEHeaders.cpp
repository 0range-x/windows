#include "buffer.h"

void PrintPEHeaders(LPVOID* pFileBuffer)
{
	if (*((PWORD)*pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("MZ�ļ���־ͷ�����ڣ�");
		free(*pFileBuffer);
		return;
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)*pFileBuffer;
	printf("**********DOSͷ**********\n");
	printf("[+]MZ���-e_magic��%x\n", pDosHeader->e_magic);
	printf("[+]PE�ļ�ƫ��-e_lfanew��%x\n", pDosHeader->e_lfanew);
	if (*((PDWORD)((DWORD)*pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("[-]NT�ļ����ǲ����ڣ�");
		free(*pFileBuffer);
		return;
	}
	//NTͷ
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)*pFileBuffer + pDosHeader->e_lfanew);
	printf("**********NTͷ**********\n");
	printf("[+]NTͷ-Signature��%x\n", pNTHeader->Signature);
	//��׼PEͷ
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	printf("**********��׼PEͷ**********\n");
	//printf("��������֧��CPU�ͺţ�%x\n", pPEHeader->Machine);
	printf("[+]�ļ�����-NumberOfSections��%x\n", pPEHeader->NumberOfSections);
	printf("[+]��ѡPEͷ��С-SizeOfOptionalHeader��%x\n", pPEHeader->SizeOfOptionalHeader);
	//��ѡPEͷ
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	printf("**********��ѡPEͷ**********\n");
	printf("˵���ļ����ͣ�%x\n", pOptionHeader->Magic);
	printf("[+]�����ļ��������-AddressOfEntryPoint��%x\n", pOptionHeader->AddressOfEntryPoint);
	printf("[+]�ڴ澵���ַ-ImageBase��%x\n", pOptionHeader->ImageBase);
	printf("[+]�ڴ����-SectionAlignment��%x\n", pOptionHeader->SectionAlignment);
	printf("[+]�ļ�����-FileAlignment��%x\n", pOptionHeader->FileAlignment);
	printf("[+]�ڴ�PE�ļ�ӳ��ߴ�-SizeOfImage��%x\n", pOptionHeader->SizeOfImage);
	printf("[+]ͷ�ͽڱ��ļ�������С-SizeOfHeaders��%x\n", pOptionHeader->SizeOfHeaders);
	

	//�ڱ����
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	printf("\n");
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		printf("�ڱ����: %d\n", i);
		printf("[+]Name: %s\n", pSectionHeader->Name);
		printf("[+]û�ж���ǰ����ʵ�ߴ�-VirtualSize: %x\n", pSectionHeader->Misc.VirtualSize);
		printf("[+]�������ڴ��е�ƫ�Ƶ�ַ-VirtualAddress: %x\n", pSectionHeader->VirtualAddress);
		printf("[+]�����ļ��ж����ĳߴ�-SizeOfRawData: %x\n", pSectionHeader->SizeOfRawData);
		printf("[+]�������ļ��е�ƫ��-PointerToRawData: %x\n", pSectionHeader->PointerToRawData);
		//printf("�ڵ�����: %x\n", pSectionHeader->Characteristics);
		printf("\n");
		pSectionHeader++;
	}
	free(*pFileBuffer);
}