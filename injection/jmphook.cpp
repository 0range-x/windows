#include "header.h"

FARPROC messageBoxAddress = NULL;
SIZE_T bytesWritten = 0;
char messageBoxOriginalBytes[6] = {};

//执行重定向的proxy function 需要接受相同的参数，具有相同的调用约定，并返回相同的类型
//只要返回值为messageboxa，就会调用该函数
int __stdcall HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	//unpatch messagebox
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, messageBoxOriginalBytes, sizeof(messageBoxOriginalBytes), &bytesWritten);
	//调用原来的messagebox
	return MessageBoxA(NULL, "hooked", "Hooked", uType);
}

void hook_messageBox() {
	//获取需要hook的dll的地址
	HINSTANCE hLibyaryName = LoadLibraryA("user32.dll");
	SIZE_T savedBuffer = 0;

	//获取内存中messageboxA函数的地址
	messageBoxAddress = GetProcAddress(hLibyaryName, "MessageBoxA");

	//保存MessageboxA中的前6个字节到bytesRead
	ReadProcessMemory(GetCurrentProcess(), messageBoxAddress, messageBoxOriginalBytes, 6, &savedBuffer);

	//创建一个patch "push <address of new MessageBoxA>; ret"
	//这里也可以用jmp指令来代替，jmp对应的指令为E9，后面跟4个字节的地址
	void* hookedMessageBoxAddress = &HookedMessageBox;
	char patch[6] = { 0 };
	memcpy_s(patch, 1, "\xE9", 1);			//push
	memcpy_s(patch + 1, 4, &hookedMessageBoxAddress, 4);  //messageboxA的地址
	//memcpy_s(patch + 5, 1, "\xC3", 1);		//ret

	//patch messageboxA(将messageboxA函数重定向到hooked函数)
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