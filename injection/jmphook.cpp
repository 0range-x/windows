#include "header.h"

FARPROC messageBoxAddress = NULL;
SIZE_T bytesWritten = 0;
char messageBoxOriginalBytes[6] = {};

//ִ���ض����proxy function ��Ҫ������ͬ�Ĳ�����������ͬ�ĵ���Լ������������ͬ������
//ֻҪ����ֵΪmessageboxa���ͻ���øú���
int __stdcall HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	//unpatch messagebox
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, messageBoxOriginalBytes, sizeof(messageBoxOriginalBytes), &bytesWritten);
	//����ԭ����messagebox
	return MessageBoxA(NULL, "hooked", "Hooked", uType);
}

void hook_messageBox() {
	//��ȡ��Ҫhook��dll�ĵ�ַ
	HINSTANCE hLibyaryName = LoadLibraryA("user32.dll");
	SIZE_T savedBuffer = 0;

	//��ȡ�ڴ���messageboxA�����ĵ�ַ
	messageBoxAddress = GetProcAddress(hLibyaryName, "MessageBoxA");

	//����MessageboxA�е�ǰ6���ֽڵ�bytesRead
	ReadProcessMemory(GetCurrentProcess(), messageBoxAddress, messageBoxOriginalBytes, 6, &savedBuffer);

	//����һ��patch "push <address of new MessageBoxA>; ret"
	//����Ҳ������jmpָ�������棬jmp��Ӧ��ָ��ΪE9�������4���ֽڵĵ�ַ
	void* hookedMessageBoxAddress = &HookedMessageBox;
	char patch[6] = { 0 };
	memcpy_s(patch, 1, "\xE9", 1);			//push
	memcpy_s(patch + 1, 4, &hookedMessageBoxAddress, 4);  //messageboxA�ĵ�ַ
	//memcpy_s(patch + 5, 1, "\xC3", 1);		//ret

	//patch messageboxA(��messageboxA�����ض���hooked����)
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, patch, sizeof(patch), &bytesWritten);
}

int main(int argc, char* argv[]) {
	//show messagebox before hooking
	MessageBoxA(NULL, "hi", "hi", MB_OK);
	hook_messageBox();
	//show messagebox after hooking
	MessageBoxA(NULL, "hi", "hi", MB_OK);
	return 0;
}