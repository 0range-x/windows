#include "demo.h"


DWORD RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva){
	//定位PE结构
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//转换地址是否在头+节表中
	if (dwRva < pOptionHeader->SizeOfHeaders)
		return dwRva;
	//遍历转换地址在哪个节中
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

	//获得导出表的文件偏移
	DWORD exportAddress = RvaToFoa(pFileBuffer, pDataDirectory[0].VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pDosHeader + exportAddress);

	printf("[+] NumberOfFunctions: %x\n", exportDirectory->NumberOfFunctions);
	printf("[+] NumberOfNames: %x\n", exportDirectory->NumberOfNames);

	int i;
	//循环遍历每个函数
	for (i = 0; i < exportDirectory->NumberOfNames; i++) {
	    printf("顺序序号:%d\t", i);
		printf("\n");
	    //导出函数名称表
	    DWORD namePointerAddress = RvaToFoa(pFileBuffer,exportDirectory->AddressOfNames + 4 * i);
	    printf("[+] namePointerAddress:%X\t", namePointerAddress);
	    //获取指向名字的指针
	    PDWORD nameAddr = (PDWORD)((DWORD)pDosHeader + namePointerAddress);
	    printf("[+] nameAddr(RVA):%X\t", *nameAddr);
	    //获取存储名字的文件偏移
	    DWORD nameOffset = RvaToFoa(pFileBuffer,*nameAddr);
	    printf("[+] nameOffset:%X\t", nameOffset);
	    //根据名字指针输出名字
	    PCHAR dllName = (PCHAR)((DWORD)pDosHeader + nameOffset);
	    printf("[+] dllName:%s\t\n", dllName);
	
	    //因为AddressOfNames与AddressOfNameOrdinals一一对应，于是可以获得对应的NameOrdinals
	    //导出函数序号表，每个函数序号占2个字节
	    DWORD OrdinalsOffset = RvaToFoa(pFileBuffer,exportDirectory->AddressOfNameOrdinals + 2 * i);
	    printf("[+] OrdinalsOffset:%X\t", OrdinalsOffset);          //文件偏移
	 
	    PWORD Ordinals = (PWORD)((DWORD)pDosHeader + OrdinalsOffset);
	    printf("[+] Ordinals:%d\t", *Ordinals);                     //地址中存储的值
	
	    //获得Ordinals后可以根据Ordinals到AddressOfFunctions中找到对应的导出函数的地址，每个索引序号对应一个地址
	    //导出函数地址表
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

	//重定位表的文件偏移
	DWORD relocateAddress= RvaToFoa(pFileBuffer, pDataDirectory[5].VirtualAddress);
	//重定位表的文件地址
	//首个重定位块
	PIMAGE_BASE_RELOCATION relocateDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)pDosHeader + relocateAddress);

	int dllCnt = 0;
	while (true)
	{
		//判断是否到达结尾，最后一个结构的VirtualAddress与 SizeofBlock 都为0 
		if (relocateDirectory->VirtualAddress != 0 && relocateDirectory->SizeOfBlock != 0) {
			//需要修复重定位项的个数
			int numofAddr = (relocateDirectory->SizeOfBlock - 8) / 2;
			for  (int i = 0; i< numofAddr; i++){
				//偏移地址，因为每个偏移地址占2个字节   所以宽度为2字节，
				PWORD offset= (PWORD)((DWORD)relocateDirectory + 8 + 2 * i);
				//高4位为0011即3
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
	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptionHeader->DataDirectory;   //数据目录是一个数组

	//计数，用来记录导入了多少个模块
	int dllCnt = 0;
	while (true){	
		//导入表的Foa地址
		DWORD importAddress = RvaToFoa(pFileBuffer, pDataDirectory[1].VirtualAddress);
		//从第一个导入表开始循环遍历，遍历完一个+一个导入表的大小到下一个导入表
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDosHeader + importAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR)* dllCnt);
		//结束条件,OriginalFirstThunk指向INT表
		if (pImportDescriptor->OriginalFirstThunk != 0) {
			DWORD nameOffset = RvaToFoa(pFileBuffer, pImportDescriptor->Name);
			char* dllName = (char*)((DWORD)pDosHeader + nameOffset);
			dllCnt++;
			DWORD OriginalFirstThunkOffset = RvaToFoa(pFileBuffer, pImportDescriptor->OriginalFirstThunk);
			if (OriginalFirstThunkOffset == -1)
				return;
			//指向INT表，存储着当前dll模块的函数名称或者函数序号
			PIMAGE_THUNK_DATA pIntTable = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + OriginalFirstThunkOffset);
			//计数，用来记录导入了该模块多少个函数
			int funcCnt = 0;
			printf("[+]  模块名：%s", dllName);
			printf("\n********************OriginalFirstThunk********************\n");
			while (true)
			{	//遍历INT表
				PIMAGE_THUNK_DATA pIntAddress = pIntTable + funcCnt;
				if (pIntAddress->u1.AddressOfData == 0) {
					break;
				}
				else
				{
					//判断最高位 ,本身有4个字节，对应的16进制代码就是0x80000000
					if ((DWORD)pIntAddress->u1.AddressOfData >= 0x80000000)
						//最高位为1
						printf("[+] 函数序号：%x\n", pIntAddress->u1.Ordinal - 0x80000000);
					else
					{
						//最高位为0,该值是一个RVA，指向IMAGE_IMPORT_BY_NAME 结构
						DWORD functionNameOffset = RvaToFoa(pFileBuffer, (DWORD)pIntAddress->u1.AddressOfData);
						PIMAGE_IMPORT_BY_NAME pFunction = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + functionNameOffset);
						printf("[+]  函数名称：%s\n",  pFunction->Name);
					}
				}
				funcCnt++;
			}

			//IAT表
			printf("\n********************FirstThunk********************\n");
			int funcCnt2 = 0;
			PIMAGE_THUNK_DATA pIatTable = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + RvaToFoa(pFileBuffer, pImportDescriptor->FirstThunk));
			while (true)
			{	//遍历IAT表
				PIMAGE_THUNK_DATA pIatAddress = pIatTable + funcCnt2;
				if (pIatAddress->u1.AddressOfData == 0) {
					break;
				}
				else
				{
					//判断最高位 ,本身有4个字节，对应的16进制代码就是0x80000000
					if ((DWORD)pIatAddress->u1.AddressOfData >= 0x80000000)
						//最高位为1
						printf("[+] 函数序号：%x\n", pIatAddress->u1.Ordinal - 0x80000000);
					else
					{
						//最高位为0,该值是一个RVA，指向IMAGE_IMPORT_BY_NAME 结构
						DWORD functionNameOffset = RvaToFoa(pFileBuffer, (DWORD)pIatAddress->u1.AddressOfData);
						PIMAGE_IMPORT_BY_NAME pFunction = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + functionNameOffset);
						printf("[+]  函数名称：%s\n", pFunction->Name);
					}
				}
				funcCnt2++;
			}
			printf("[+]  函数数量：%d\n\n",funcCnt);
		}
		else
		{
			break;
		}
	}
	printf("[+] 引用模块数: %d\n", dllCnt);
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
//	//判断空间是否足够,可以添加一个表
//	//判断条件
//	//sizeofHeader - （DOS + 垃圾数据 + PE标记 + 标准PE头 + 可选PE头 + 已存在节表）>= 2个节表的大小
//	whiteSpaceSize = pOptionHeader->SizeOfHeaders - (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader) + ((pPEHeader->NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER));
//	if (whiteSpaceSize < sizeof(IMAGE_SECTION_HEADER)) {
//		printf("[-] 数据缓冲区太小无法添加节表.");
//		return false;
//	}
//
//	//copy 一个新的节表
//	char* pTmpFile = (char*)pFileBuffer;
//	char* pTmpFileCopy = (char*)pFileBuffer;
//	//第一个节表开始的地方
//	pTmpFile = pTmpFile + (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader);
//	//最后一个节表的结尾
//	pTmpFileCopy = pTmpFileCopy + (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader + ((pPEHeader->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER)));
//	memcpy(pTmpFileCopy, pTmpFile, sizeof(IMAGE_SECTION_HEADER));
//
//	//修改pe中节的数量
//	pPEHeader->NumberOfSections += 1;
//	//修改sizeofImage大小
//	pOptionHeader->SizeOfImage += SectionTableSize;
//
//	//在原有数据最后，新增一个节的数据(内存对齐的整数倍)
//	//使用PE结构计算文件大小
//	PIMAGE_SECTION_HEADER pTempSectionHeaderTo = pSectionHeader;
//	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
//		pTempSectionHeaderTo++;
//
//	DWORD fileSize = pTempSectionHeaderTo->SizeOfRawData + pTempSectionHeaderTo->PointerToRawData;
//	//申请file空间大小
//	*pNewBuffer = (PDWORD)malloc(fileSize + SectionTableSize);
//	if (!pNewBuffer) {
//		printf("申请ImageBuffer失败");
//		free(*pNewBuffer);
//		return false;
//	}
//
//	memset(*pNewBuffer, 0, fileSize + SectionTableSize);
//	//修正节表属性
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
//	//重定位表的文件偏移
//	DWORD relocateAddress = RvaToFoa(pFileBuffer, pRelocateDataDirectory.VirtualAddress);
//	//重定位表的文件地址
//	//首个重定位块
//	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pDosHeader + relocateAddress);
//
//	//计数，计算总的重定向表的大小
//	DWORD count = 0;
//	size_t num = 1;
//	for (size_t i = 1; pRelocation->VirtualAddress&&pRelocation->SizeOfBlock; i++)
//	{
//		count += pRelocation->SizeOfBlock;
//		printf("[+] VirtualAddress: %x\n[+]SizeOfBlock: %x\n", pRelocation->VirtualAddress, pRelocation->SizeOfBlock);
//		pRelocation = (PIMAGE_BASE_RELOCATION)((BYTE*)pRelocation + pRelocation->SizeOfBlock);
//		num++;
//	}
//	printf("重定位表的总大小是： %x字节  %x字  %x双字\n 表的数目是： %d\n", count, (count / 2), (count / 4), num);
//
//	//开始重新分配新空间
//	DWORD size = 0;			//加上重定位表以后的内存的总大小
//	DWORD SectionOneFoa = 0;
//	DWORD  FOA = 0;
//
//	//节中的PointertoRawData 可以算出整个节的大小
//	//定位到最后一个节
//	for (size_t i = 0; i < pPEHeader->NumberOfSections; i++)
//	{
//		printf("[+]%s\n", pSectionHeader->Name);
//		pSectionHeader++;
//	}
//	//最后一个节
//	printf("[+]Last Section\n [+] Name:%s\t PointerToRawData:%x\tSizeOfRawData:%x\n", pSectionHeader->Name, pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
//	
//	//计算出该申请空间的大小   如果重定向表的大小小于文件对齐的大小，那么加上文件对齐的大小
//	size = pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData + pOptionHeader->FileAlignment;
//	pOptionHeader->SizeOfImage += 400;
//	printf("内存总大小：%x\n", size);
//
//	//将节表移动到第一个节表
//	for (size_t i = 0; i < pPEHeader->NumberOfSections; i++)
//	{
//		printf("%s\n", pSectionHeader->Name);
//		pSectionHeader--;
//	}
//	printf("[+] First Section dllName: %s", pSectionHeader->Name);
//	
//	LPVOID newBuffer = malloc(size);
//	if (!newBuffer) {
//		printf("内存申请失败");
//		free(newBuffer);
//		free(pFileBuffer);
//		return;
//	}
//
//	memset(newBuffer, 0, size);
//	//复制头
//	memcpy(newBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);
//	
//	//复制节表
//	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
//
//	for (size_t i = 1; i < pPEHeader->NumberOfSections; i++,pSectionHeader++,pTempSectionHeader--)
//	{
//		//memcpy异常，有错误
//		memcpy((void*)((DWORD)newBuffer + pTempSectionHeader->PointerToRawData),
//			(void*)((DWORD)pPEHeader + pSectionHeader->PointerToRawData),
//			pSectionHeader->SizeOfRawData);
//		printf("[+] pTempSectionHeader->Name:%s\t", pTempSectionHeader->Name);
//	}
//
//	//将原始节表指针移动到初始位置
//	for (size_t i = 0; i < pPEHeader->NumberOfSections; i++,pSectionHeader--)
//		printf("[+] pSectionHeader->Name: %s", pSectionHeader->Name);
//
//
//
//
//	//为新的内存空间的属性的节更改数据
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
//	printf("最后一个节的结尾地址是：%x\n", (pTempSectionHeader->PointerToRawData + pTempSectionHeader->SizeOfRawData));
//	//新添加一个节，然后移动重定位表，先将重定位表移动过来，然后再将原来的重定位表清零，全部填充为00
//	//新增节
//	printf("原节表数目为: %d\n", pNewPEHeader->NumberOfSections);
//	pNewPEHeader->NumberOfSections++;
//	printf("现节表数目为: %d\n", pNewPEHeader->NumberOfSections);
//
//	//定位到新增的节表的位置
//	for (size_t i = 0; i < pNewPEHeader->NumberOfSections; i++, pNewSectionHeader++);
//
//
//	//为新节表赋值
//	pNewSectionHeader->Characteristics = 0x20000060;
//	pNewSectionHeader->PointerToLinenumbers = 0;
//	pNewSectionHeader->NumberOfRelocations = 0;
//	pNewSectionHeader->PointerToRawData = 0x7600;
//	pNewSectionHeader->PointerToRelocations = 0;
//	pNewSectionHeader->SizeOfRawData = 0x400;
//	//VirtualAddress 的大小是上一个节的VirtualAddress + virtualSize
//	pNewSectionHeader->VirtualAddress = pTempSectionHeader->VirtualAddress + pTempSectionHeader->Misc.VirtualSize;
//	pNewSectionHeader->Misc.VirtualSize = pNewOptionHeader->SectionAlignment;
//	pSectionHeader->Name[0] = '.';
//	pSectionHeader->Name[1] = 'n';
//	pSectionHeader->Name[2] = 'e';
//	pSectionHeader->Name[3] = 'w';
//
//
//	//将重定位表的数据移动到新的内存空间(新增节表的地方)   然后memcpy 到新增的节表处， 先修改完VirtualAddress
//	//移动到最后一个节表
//	for (size_t i = 0; i < 5; i++, pNewDataDirectory++);
//	pNewDataDirectory->VirtualAddress = pNewSectionHeader->VirtualAddress + pNewSectionHeader->Misc.VirtualSize;  //文件地址
//
//	//根据重定位表的大小分配空间
//	LPVOID Relocation = NULL;
//	Relocation = malloc(2 * pOptionHeader->FileAlignment);
//	memset(Relocation, 0, 2 * pOptionHeader->FileAlignment);
//
//	//将数据目录项里重定位表的文件地址开始的地方复制到新的节表的文件地址开始的地方
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
	//根据文件句柄创建映射
	HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
	if (FAILED(hMap)) {
		printf("[-] Failed to CreateFileMappingA.\n[-] Error:%d", GetLastError());
		return -1;
	}
	//映射内容
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