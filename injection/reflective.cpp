#include "header.h"


//HANDLE GetProcessHandle(int nID)
//{
//	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, nID);
//}
//
//HANDLE GetProcessIdByName(LPCTSTR lpszProcessName)
//{
//	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//	if (hSnapshot == INVALID_HANDLE_VALUE)
//	{
//		return 0;
//	}
//
//	PROCESSENTRY32 pe;
//	pe.dwSize = sizeof pe;
//
//	if (Process32First(hSnapshot, &pe))
//	{
//		do {
//			if (lstrcmpi(lpszProcessName, pe.szExeFile) == 0)
//			{
//				CloseHandle(hSnapshot);
//				return  GetProcessHandle(pe.th32ProcessID);
//			}
//		} while (Process32Next(hSnapshot, &pe));
//	}
//
//	CloseHandle(hSnapshot);
//	return 0;
//}


BOOL reflectiveLoader(LPCSTR dllPath) {
	//��ȡ��ǰģ����ڴ�ӳ���ַ
	//PVOID imagebase = GetModuleHandleA((LPCSTR)GetProcessIdByName(dllPath));
	PVOID imagebase = GetModuleHandleA(NULL);
	if (imagebase == NULL) {
		printf("[-] Failed to GetModuleHandleA. Error: %d\n", GetLastError());
		return false;
	}
	HANDLE hdllName = CreateFileA(dllPath,GENERIC_READ,NULL,NULL,OPEN_EXISTING,NULL,NULL);
	DWORD dwdllSize = GetFileSize(hdllName,NULL);
	LPVOID pFileBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwdllSize);
	DWORD dwoutSize = 0;
	//��dllpath�Ĳ������뻺����
	ReadFile(hdllName, pFileBuffer, dwdllSize, &dwoutSize, NULL);

	//����peͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//dllӳ�䵽�ڴ��Ĵ�С
	SIZE_T dllImageSize = pOptionHeader->SizeOfImage;

	//��dll����һ���ڴ棬dll���ڴ��е���ʼ��ַ
	LPVOID pdllBase = VirtualAlloc((LPVOID)pOptionHeader->SizeOfImage, dllImageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	//����ƫ��,dll��ʼ��ַ��imagebase��ƫ��
	DWORD_PTR deltaImageBase = (DWORD)pdllBase - (DWORD_PTR)pOptionHeader->ImageBase;

	//copy dllͷ���µĿռ�
	memcpy(pdllBase, pFileBuffer, pOptionHeader->SizeOfHeaders);
	memcpy(pdllBase, 0, pOptionHeader->SizeOfHeaders);

	//copy dll�ڱ�
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		//�ڴ��еĴ������Ľ�
		LPVOID pSectionDestination = (LPVOID)((DWORD)pdllBase + pSectionHeader->VirtualAddress);
		//�ڵ��ļ�ͷ�Ĵ�С
		LPVOID pSectionBytes = (LPVOID)((DWORD)pFileBuffer + pSectionHeader->PointerToRawData);
		memcpy(pSectionDestination, pSectionBytes, pSectionHeader->SizeOfRawData);
		pSectionHeader++;
	}

	//ӳ���ַ�ض�λ
	//�ض�λĿ¼
	IMAGE_DATA_DIRECTORY relocationDataDirectory = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	
	//�׸��ض�λ��
	DWORD_PTR relocationTable = relocationDataDirectory.VirtualAddress + (DWORD_PTR)pdllBase;
	DWORD relocationsProcessed = 0;

	while (relocationsProcessed < relocationDataDirectory.Size)
	{
		//ÿһ���ض�λ�����ʼ��ַ
		PIMAGE_BASE_RELOCATION relocationBlock = (PIMAGE_BASE_RELOCATION)(relocationTable + relocationsProcessed);
		relocationsProcessed += sizeof(IMAGE_BASE_RELOCATION);
		DWORD relocationCount = (relocationBlock->SizeOfBlock - 8) / 2;
		
		//�ض�λ�����ڵ�ַ
		PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);
		for (DWORD i = 0; i < relocationCount; i++){
			relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);
			if (relocationEntries[i].Type == 0)
				continue;
			//��Ҫ�޸��ض�λ�ĵ�ַ
			DWORD_PTR relocationRVA = relocationBlock->VirtualAddress + relocationEntries[i].Offset;
			DWORD_PTR addressToPatch = 0;     //������������������Ҫ�ض�λ�ĵ�ַ
			ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)pdllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
			addressToPatch += deltaImageBase;
			memcpy((PVOID)((DWORD_PTR)pdllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
		}
	}


	//�޸�IAT��
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importDirectory = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importDirectory.VirtualAddress + (DWORD_PTR)pdllBase);
	LPCSTR libraryName = "";
	HMODULE hLibrary = NULL;
	//�������е����
	while (importDescriptor->Name!=NULL)
	{
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)pdllBase;
		hLibrary = LoadLibraryA(libraryName);
		if (hLibrary) {
			PIMAGE_THUNK_DATA thunk = NULL;
			//ָ��IAT��ָ��
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)pdllBase + importDescriptor->FirstThunk);
			while (thunk->u1.AddressOfData!=NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
					//���ݺ�����Ż�ȡ������ַ
					LPCSTR functionOrdial = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
					thunk->u1.Function = (DWORD_PTR)GetProcAddress(hLibrary, libraryName);
				}
				else
				{	//���ݺ������ֻ�ȡ������ַ
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)pdllBase + thunk->u1.AddressOfData);
					thunk->u1.Function = (DWORD_PTR)GetProcAddress(hLibrary, functionName->Name);
				}
				thunk++;
			}
		}
		importDescriptor++;
	}

	DLLEntry DllEntry = (DLLEntry)((DWORD_PTR)pdllBase + pOptionHeader->AddressOfEntryPoint);
	(*DllEntry)((HINSTANCE)pdllBase, DLL_PROCESS_ATTACH, 0);
	printf("[+] Reflective inject successfully.");
	CloseHandle(hdllName);
	HeapFree(GetProcessHeap(), 0, pFileBuffer);
	return true;
}

int main(int argc,char* argv[]) {
	LPCSTR dllPath = "C:\\users\\hack\\desktop\\test\\Dll.dll";
	if (strcmp(argv[1],"re") ==0 ){
		reflectiveLoader(dllPath);
		return 0;
	}
	else
	{
		exit;
	}


}