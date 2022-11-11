#include "header.h"

//定义MessageBoxA的函数原型
using PrototypeMessageBox = int (WINAPI*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
//保存原来的MessageBoxA的地址
PrototypeMessageBox originalMsgBox = MessageBoxA;
//hooked function
int hookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	MessageBoxW(NULL, L"1", L"1", MB_OK);
	//执行原来的MessageBoxA
	return originalMsgBox(hWnd, "hooked", "hooked", uType);
}

void IATHook() {
	LPVOID imageBase = GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + pDosHeader->e_lfanew);
	IMAGE_DATA_DIRECTORY importsDirectory = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
	LPCSTR libraryName = NULL;
	HMODULE library = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL;
	//遍历所有dll
	while (importDescriptor->Name != NULL)
	{
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;
		library = LoadLibraryA(libraryName);

		if (library) {
			PIMAGE_THUNK_DATA firstThunk = NULL, originalFirstThunk = NULL;
			originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
			firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

			//遍历所有函数模块
			while (originalFirstThunk->u1.AddressOfData != NULL)
			{
				functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);

				//找到messageboxA的地址
				if (strcmp(functionName->Name, "MessageBoxA") == 0) {
					SIZE_T bytesWritten = 0;
					DWORD oldProtect = 0;
					VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
					//用hook函数替换MessageBoxA函数
					firstThunk->u1.Function = (DWORD_PTR)hookedMessageBox;
				}
				originalFirstThunk++;
				firstThunk++;
			}
		}
		importDescriptor++;
	}
}

int main(int argc, char* argv[]) {
	//hook IAT 之前
	MessageBoxA(NULL, "hello", "hello", MB_OK);
	IATHook();
	//hook之后
	MessageBoxA(NULL, "hack", "hack", MB_OK);
	return 0;
}