#include "demo.h"


DWORD RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva){
	//��λPE�ṹ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//ת����ַ�Ƿ���ͷ+�ڱ���
	if (dwRva < pOptionHeader->SizeOfHeaders)
		return dwRva;
	//����ת����ַ���ĸ�����
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++){
		if ((dwRva >= pSectionHeader[i].VirtualAddress) && (dwRva < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize))
			return dwRva - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
	}
	return 0;
}

void getExportTable(LPVOID pFileBuffer) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptionHeader->DataDirectory;

	//��õ�������ļ�ƫ��
	DWORD exportAddress = RvaToFoa(pFileBuffer, pDataDirectory[0].VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pDosHeader + exportAddress);

	printf("[+] NumberOfFunctions: %x\n", exportDirectory->NumberOfFunctions);
	printf("[+] NumberOfNames: %x\n", exportDirectory->NumberOfNames);

	int i;
	//ѭ������ÿ������
	for (i = 0; i < exportDirectory->NumberOfNames; i++) {
	    printf("˳�����:%d\t", i);
		printf("\n");
	    //�����������Ʊ�
	    DWORD namePointerAddress = RvaToFoa(pFileBuffer,exportDirectory->AddressOfNames + 4 * i);
	    printf("[+] namePointerAddress:%X\t", namePointerAddress);
	    //��ȡָ�����ֵ�ָ��
	    PDWORD nameAddr = (PDWORD)((DWORD)pDosHeader + namePointerAddress);
	    printf("[+] nameAddr(RVA):%X\t", *nameAddr);
	    //��ȡ�洢���ֵ��ļ�ƫ��
	    DWORD nameOffset = RvaToFoa(pFileBuffer,*nameAddr);
	    printf("[+] nameOffset:%X\t", nameOffset);
	    //��������ָ���������
	    PCHAR dllName = (PCHAR)((DWORD)pDosHeader + nameOffset);
	    printf("[+] dllName:%s\t\n", dllName);
	
	    //��ΪAddressOfNames��AddressOfNameOrdinalsһһ��Ӧ�����ǿ��Ի�ö�Ӧ��NameOrdinals
	    //����������ű�ÿ���������ռ2���ֽ�
	    DWORD OrdinalsOffset = RvaToFoa(pFileBuffer,exportDirectory->AddressOfNameOrdinals + 2 * i);
	    printf("[+] OrdinalsOffset:%X\t", OrdinalsOffset);          //�ļ�ƫ��
	 
	    PWORD Ordinals = (PWORD)((DWORD)pDosHeader + OrdinalsOffset);
	    printf("[+] Ordinals:%d\t", *Ordinals);                     //��ַ�д洢��ֵ
	
	    //���Ordinals����Ը���Ordinals��AddressOfFunctions���ҵ���Ӧ�ĵ��������ĵ�ַ��ÿ��������Ŷ�Ӧһ����ַ
	    //����������ַ��
	    PDWORD functionAddress = (PDWORD)((DWORD)pDosHeader + RvaToFoa(pFileBuffer,exportDirectory->AddressOfFunctions+ 4 * *Ordinals));
	    printf("[+] functionAddress(RVA):%X\n\n", *functionAddress);
	}
	
}

void getRelocationTable(LPVOID pFileBuffer) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptionHeader->DataDirectory;
	printf("[+] dos->magic:%x\n", pDosHeader->e_magic);

	//�ض�λ����ļ�ƫ��
	DWORD relocateAddress= RvaToFoa(pFileBuffer, pDataDirectory[5].VirtualAddress);
	//�ض�λ����ļ���ַ
	//�׸��ض�λ��
	PIMAGE_BASE_RELOCATION relocateDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)pDosHeader + relocateAddress);

	int dllCnt = 0;
	while (true)
	{
		//�ж��Ƿ񵽴��β�����һ���ṹ��VirtualAddress�� SizeofBlock ��Ϊ0 
		if (relocateDirectory->VirtualAddress != 0 && relocateDirectory->SizeOfBlock != 0) {
			//��Ҫ�޸��ض�λ��ĸ���
			int numofAddr = (relocateDirectory->SizeOfBlock - 8) / 2;
			for  (int i = 0; i< numofAddr; i++){
				//ƫ�Ƶ�ַ����Ϊÿ��ƫ�Ƶ�ַռ2���ֽ�   ���Կ��Ϊ2�ֽڣ�
				PWORD offset= (PWORD)((DWORD)relocateDirectory + 8 + 2 * i);
				//��4λΪ0011��3
				if (*offset >= 0x3000) 
					printf("[+] base:%x\toffset: %x\n", relocateDirectory->VirtualAddress, *offset - 0x3000);
			}
			relocateDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)relocateDirectory + relocateDirectory->SizeOfBlock);
			dllCnt++;
			printf("\n");
		}
		else
		{
			break;
		}
	}
	printf("%d\n", dllCnt);
	return;
}

DWORD Align(DWORD size, DWORD ALIGN_BASE){
    assert(0 != ALIGN_BASE);
    if (size % ALIGN_BASE){
        size = (size / ALIGN_BASE + 1) * ALIGN_BASE;
    }
    return size;
}


void getImportTable(LPVOID pFileBuffer) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptionHeader->DataDirectory;   //����Ŀ¼��һ������

	//������������¼�����˶��ٸ�ģ��
	int dllCnt = 0;
	while (true){	
		//������Foa��ַ
		DWORD importAddress = RvaToFoa(pFileBuffer, pDataDirectory[1].VirtualAddress);
		//�ӵ�һ�������ʼѭ��������������һ��+һ�������Ĵ�С����һ�������
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDosHeader + importAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR)* dllCnt);
		//��������,OriginalFirstThunkָ��INT��
		if (pImportDescriptor->OriginalFirstThunk != 0) {
			DWORD nameOffset = RvaToFoa(pFileBuffer, pImportDescriptor->Name);
			char* dllName = (char*)((DWORD)pDosHeader + nameOffset);
			dllCnt++;
			DWORD OriginalFirstThunkOffset = RvaToFoa(pFileBuffer, pImportDescriptor->OriginalFirstThunk);
			if (OriginalFirstThunkOffset == -1)
				return;
			//ָ��INT���洢�ŵ�ǰdllģ��ĺ������ƻ��ߺ������
			PIMAGE_THUNK_DATA pIntTable = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + OriginalFirstThunkOffset);
			//������������¼�����˸�ģ����ٸ�����
			int funcCnt = 0;
			printf("[+]  ģ������%s", dllName);
			printf("\n********************OriginalFirstThunk********************\n");
			while (true)
			{	//����INT��
				PIMAGE_THUNK_DATA pIntAddress = pIntTable + funcCnt;
				if (pIntAddress->u1.AddressOfData == 0) {
					break;
				}
				else
				{
					//�ж����λ ,������4���ֽڣ���Ӧ��16���ƴ������0x80000000
					if ((DWORD)pIntAddress->u1.AddressOfData >= 0x80000000)
						//���λΪ1
						printf("[+] ������ţ�%x\n", pIntAddress->u1.Ordinal - 0x80000000);
					else
					{
						//���λΪ0,��ֵ��һ��RVA��ָ��IMAGE_IMPORT_BY_NAME �ṹ
						DWORD functionNameOffset = RvaToFoa(pFileBuffer, (DWORD)pIntAddress->u1.AddressOfData);
						PIMAGE_IMPORT_BY_NAME pFunction = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + functionNameOffset);
						printf("[+]  �������ƣ�%s\n",  pFunction->Name);
					}
				}
				funcCnt++;
			}

			//IAT��
			printf("\n********************FirstThunk********************\n");
			int funcCnt2 = 0;
			PIMAGE_THUNK_DATA pIatTable = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + RvaToFoa(pFileBuffer, pImportDescriptor->FirstThunk));
			while (true)
			{	//����IAT��
				PIMAGE_THUNK_DATA pIatAddress = pIatTable + funcCnt2;
				if (pIatAddress->u1.AddressOfData == 0) {
					break;
				}
				else
				{
					//�ж����λ ,������4���ֽڣ���Ӧ��16���ƴ������0x80000000
					if ((DWORD)pIatAddress->u1.AddressOfData >= 0x80000000)
						//���λΪ1
						printf("[+] ������ţ�%x\n", pIatAddress->u1.Ordinal - 0x80000000);
					else
					{
						//���λΪ0,��ֵ��һ��RVA��ָ��IMAGE_IMPORT_BY_NAME �ṹ
						DWORD functionNameOffset = RvaToFoa(pFileBuffer, (DWORD)pIatAddress->u1.AddressOfData);
						PIMAGE_IMPORT_BY_NAME pFunction = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + functionNameOffset);
						printf("[+]  �������ƣ�%s\n", pFunction->Name);
					}
				}
				funcCnt2++;
			}
			printf("[+]  ����������%d\n\n",funcCnt);
		}
		else
		{
			break;
		}
	}
	printf("[+] ����ģ����: %d\n", dllCnt);
}

//BOOL AddFileBufferToSectionTable(IN LPVOID pFileBuffer) {
//	LPVOID* pNewBuffer = 0;
//	const char* sectionTable;
//	size_t SectionTableSize;
//	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
//	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
//	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 0x4);
//	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
//	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
//
//	DWORD whiteSpaceSize = 0;
//
//	//�жϿռ��Ƿ��㹻,�������һ����
//	//�ж�����
//	//sizeofHeader - ��DOS + �������� + PE��� + ��׼PEͷ + ��ѡPEͷ + �Ѵ��ڽڱ�>= 2���ڱ�Ĵ�С
//	whiteSpaceSize = pOptionHeader->SizeOfHeaders - (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader) + ((pPEHeader->NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER));
//	if (whiteSpaceSize < sizeof(IMAGE_SECTION_HEADER)) {
//		printf("[-] ���ݻ�����̫С�޷���ӽڱ�.");
//		return false;
//	}
//
//	//copy һ���µĽڱ�
//	char* pTmpFile = (char*)pFileBuffer;
//	char* pTmpFileCopy = (char*)pFileBuffer;
//	//��һ���ڱ�ʼ�ĵط�
//	pTmpFile = pTmpFile + (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader);
//	//���һ���ڱ�Ľ�β
//	pTmpFileCopy = pTmpFileCopy + (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader + ((pPEHeader->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER)));
//	memcpy(pTmpFileCopy, pTmpFile, sizeof(IMAGE_SECTION_HEADER));
//
//	//�޸�pe�нڵ�����
//	pPEHeader->NumberOfSections += 1;
//	//�޸�sizeofImage��С
//	pOptionHeader->SizeOfImage += SectionTableSize;
//
//	//��ԭ�������������һ���ڵ�����(�ڴ�����������)
//	//ʹ��PE�ṹ�����ļ���С
//	PIMAGE_SECTION_HEADER pTempSectionHeaderTo = pSectionHeader;
//	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
//		pTempSectionHeaderTo++;
//
//	DWORD fileSize = pTempSectionHeaderTo->SizeOfRawData + pTempSectionHeaderTo->PointerToRawData;
//	//����file�ռ��С
//	*pNewBuffer = (PDWORD)malloc(fileSize + SectionTableSize);
//	if (!pNewBuffer) {
//		printf("����ImageBufferʧ��");
//		free(*pNewBuffer);
//		return false;
//	}
//
//	memset(*pNewBuffer, 0, fileSize + SectionTableSize);
//	//�����ڱ�����
//	PIMAGE_SECTION_HEADER pTempSectionHeaderTo2 = (PIMAGE_SECTION_HEADER)pTmpFileCopy;
//
//	memcpy(pTempSectionHeaderTo2->Name, sectionTable, 4);
//	pTempSectionHeaderTo2->Misc.VirtualSize = SectionTableSize;
//	pTempSectionHeaderTo2->VirtualAddress = pTempSectionHeaderTo->VirtualAddress + Align(pTempSectionHeaderTo->Misc.VirtualSize, pOptionHeader->SectionAlignment);
//	pTempSectionHeaderTo2->SizeOfRawData = Align(SectionTableSize, pOptionHeader->FileAlignment);
//	pTempSectionHeaderTo2->PointerToRawData = pTempSectionHeaderTo->PointerToRawData + Align(pTempSectionHeaderTo->SizeOfRawData, pOptionHeader->FileAlignment);
//	memcpy(*pNewBuffer, pFileBuffer, fileSize);
//	return true;
//
//}

//void moveReloc(LPVOID pFileBuffer) {
//	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
//	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
//	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 0x4);
//	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
//	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
//
//	IMAGE_DATA_DIRECTORY pRelocateDataDirectory = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
//	printf("[+] pRelocateDataDirectory(RVA): %x \n", pRelocateDataDirectory.VirtualAddress);
//
//	//�ض�λ����ļ�ƫ��
//	DWORD relocateAddress = RvaToFoa(pFileBuffer, pRelocateDataDirectory.VirtualAddress);
//	//�ض�λ����ļ���ַ
//	//�׸��ض�λ��
//	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pDosHeader + relocateAddress);
//
//	//�����������ܵ��ض����Ĵ�С
//	DWORD count = 0;
//	size_t num = 1;
//	for (size_t i = 1; pRelocation->VirtualAddress&&pRelocation->SizeOfBlock; i++)
//	{
//		count += pRelocation->SizeOfBlock;
//		printf("[+] VirtualAddress: %x\n[+]SizeOfBlock: %x\n", pRelocation->VirtualAddress, pRelocation->SizeOfBlock);
//		pRelocation = (PIMAGE_BASE_RELOCATION)((BYTE*)pRelocation + pRelocation->SizeOfBlock);
//		num++;
//	}
//	printf("�ض�λ����ܴ�С�ǣ� %x�ֽ�  %x��  %x˫��\n �����Ŀ�ǣ� %d\n", count, (count / 2), (count / 4), num);
//
//	//��ʼ���·����¿ռ�
//	DWORD size = 0;			//�����ض�λ���Ժ���ڴ���ܴ�С
//	DWORD SectionOneFoa = 0;
//	DWORD  FOA = 0;
//
//	//���е�PointertoRawData ������������ڵĴ�С
//	//��λ�����һ����
//	for (size_t i = 0; i < pPEHeader->NumberOfSections; i++)
//	{
//		printf("[+]%s\n", pSectionHeader->Name);
//		pSectionHeader++;
//	}
//	//���һ����
//	printf("[+]Last Section\n [+] Name:%s\t PointerToRawData:%x\tSizeOfRawData:%x\n", pSectionHeader->Name, pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
//	
//	//�����������ռ�Ĵ�С   ����ض����Ĵ�СС���ļ�����Ĵ�С����ô�����ļ�����Ĵ�С
//	size = pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData + pOptionHeader->FileAlignment;
//	pOptionHeader->SizeOfImage += 400;
//	printf("�ڴ��ܴ�С��%x\n", size);
//
//	//���ڱ��ƶ�����һ���ڱ�
//	for (size_t i = 0; i < pPEHeader->NumberOfSections; i++)
//	{
//		printf("%s\n", pSectionHeader->Name);
//		pSectionHeader--;
//	}
//	printf("[+] First Section dllName: %s", pSectionHeader->Name);
//	
//	LPVOID newBuffer = malloc(size);
//	if (!newBuffer) {
//		printf("�ڴ�����ʧ��");
//		free(newBuffer);
//		free(pFileBuffer);
//		return;
//	}
//
//	memset(newBuffer, 0, size);
//	//����ͷ
//	memcpy(newBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);
//	
//	//���ƽڱ�
//	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
//
//	for (size_t i = 1; i < pPEHeader->NumberOfSections; i++,pSectionHeader++,pTempSectionHeader--)
//	{
//		//memcpy�쳣���д���
//		memcpy((void*)((DWORD)newBuffer + pTempSectionHeader->PointerToRawData),
//			(void*)((DWORD)pPEHeader + pSectionHeader->PointerToRawData),
//			pSectionHeader->SizeOfRawData);
//		printf("[+] pTempSectionHeader->Name:%s\t", pTempSectionHeader->Name);
//	}
//
//	//��ԭʼ�ڱ�ָ���ƶ�����ʼλ��
//	for (size_t i = 0; i < pPEHeader->NumberOfSections; i++,pSectionHeader--)
//		printf("[+] pSectionHeader->Name: %s", pSectionHeader->Name);
//
//
//
//
//	//Ϊ�µ��ڴ�ռ�����ԵĽڸ�������
//	PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER)newBuffer;
//	PIMAGE_NT_HEADERS pNewNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pNewDosHeader + pNewDosHeader->e_lfanew);
//	PIMAGE_FILE_HEADER pNewPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNewNTHeader) + 4);
//	PIMAGE_OPTIONAL_HEADER32 pNewOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pNewPEHeader + IMAGE_SIZEOF_FILE_HEADER);
//	PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNewOptionHeader + pNewPEHeader->SizeOfOptionalHeader);
//	PIMAGE_DATA_DIRECTORY pNewDataDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)pNewOptionHeader + 96);
//
//	PIMAGE_BASE_RELOCATION pNewRelocation = NULL;
//
//
//	printf("���һ���ڵĽ�β��ַ�ǣ�%x\n", (pTempSectionHeader->PointerToRawData + pTempSectionHeader->SizeOfRawData));
//	//�����һ���ڣ�Ȼ���ƶ��ض�λ���Ƚ��ض�λ���ƶ�������Ȼ���ٽ�ԭ�����ض�λ�����㣬ȫ�����Ϊ00
//	//������
//	printf("ԭ�ڱ���ĿΪ: %d\n", pNewPEHeader->NumberOfSections);
//	pNewPEHeader->NumberOfSections++;
//	printf("�ֽڱ���ĿΪ: %d\n", pNewPEHeader->NumberOfSections);
//
//	//��λ�������Ľڱ��λ��
//	for (size_t i = 0; i < pNewPEHeader->NumberOfSections; i++, pNewSectionHeader++);
//
//
//	//Ϊ�½ڱ�ֵ
//	pNewSectionHeader->Characteristics = 0x20000060;
//	pNewSectionHeader->PointerToLinenumbers = 0;
//	pNewSectionHeader->NumberOfRelocations = 0;
//	pNewSectionHeader->PointerToRawData = 0x7600;
//	pNewSectionHeader->PointerToRelocations = 0;
//	pNewSectionHeader->SizeOfRawData = 0x400;
//	//VirtualAddress �Ĵ�С����һ���ڵ�VirtualAddress + virtualSize
//	pNewSectionHeader->VirtualAddress = pTempSectionHeader->VirtualAddress + pTempSectionHeader->Misc.VirtualSize;
//	pNewSectionHeader->Misc.VirtualSize = pNewOptionHeader->SectionAlignment;
//	pSectionHeader->Name[0] = '.';
//	pSectionHeader->Name[1] = 'n';
//	pSectionHeader->Name[2] = 'e';
//	pSectionHeader->Name[3] = 'w';
//
//
//	//���ض�λ��������ƶ����µ��ڴ�ռ�(�����ڱ�ĵط�)   Ȼ��memcpy �������Ľڱ��� ���޸���VirtualAddress
//	//�ƶ������һ���ڱ�
//	for (size_t i = 0; i < 5; i++, pNewDataDirectory++);
//	pNewDataDirectory->VirtualAddress = pNewSectionHeader->VirtualAddress + pNewSectionHeader->Misc.VirtualSize;  //�ļ���ַ
//
//	//�����ض�λ��Ĵ�С����ռ�
//	LPVOID Relocation = NULL;
//	Relocation = malloc(2 * pOptionHeader->FileAlignment);
//	memset(Relocation, 0, 2 * pOptionHeader->FileAlignment);
//
//	//������Ŀ¼�����ض�λ����ļ���ַ��ʼ�ĵط����Ƶ��µĽڱ���ļ���ַ��ʼ�ĵط�
//	memcpy((void*)(pNewSectionHeader->PointerToRawData), ((void*)((DWORD)pFileBuffer + relocationFPA)), 0x320);
//
//	size_t size_ = 0;
//	size_ = (pNewSectionHeader->PointerToRawData + pNewSectionHeader->SizeOfRawData);
//	//SaveFile(newBuffer, size_, OUTFILEPATH);
//	//WriteFile()
//	free(pFileBuffer);
//	free(Relocation);
//	free(newBuffer);
//
//
//}
//


int main(int argc, char* argv[]) {
	HANDLE hFile = CreateFileA("E:\\fg.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
	if (FAILED(hFile)) {
		printf("[-] Failed to CreateFileA.\n[-] Error:%d", GetLastError());
		return -1;
	}
	//�����ļ��������ӳ��
	HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
	if (FAILED(hMap)) {
		printf("[-] Failed to CreateFileMappingA.\n[-] Error:%d", GetLastError());
		return -1;
	}
	//ӳ������
	LPVOID pFile = MapViewOfFile(hMap, FILE_SHARE_WRITE, 0, 0, 0);
	if (FAILED(pFile)) {
		printf("[-] Failed to MapViewOfFile.\n[-] Error:%d", GetLastError());
		return -1;
	}
	//getRelocationTable(pFile);
	//getExportTable(pFile);
	getImportTable(pFile);
	UnmapViewOfFile(pFile);
	CloseHandle(hFile);
	return 0;

}