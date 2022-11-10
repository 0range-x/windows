#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include<TlHelp32.h>
#include<stdio.h>

//DWORD GetPid(LPCWSTR findname)
//{
//    PROCESSENTRY32 pe32 = { 0 };
//    pe32.dwSize = sizeof(pe32);
//    HANDLE hprocess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//    BOOL bRet = Process32First(hprocess, &pe32);
//    while (bRet)
//    {
//        if (strcmp(findname, pe32.szExeFile) == 0)
//        {
//            //wprintf(L"%-ls , %40ld\n", pe32.szExeFile, pe32.th32ProcessID);
//            return pe32.th32ProcessID;              //pid
//        }
//        bRet = Process32Next(hprocess, &pe32);
//    }
//}

BOOL reversePid() {

        PROCESSENTRY32 pe32 = { 0 };
        pe32.dwSize = sizeof(PROCESSENTRY32);
        HANDLE hprocess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        BOOL bRet = Process32First(hprocess, &pe32);
        while (bRet)
        {
            printf("[%d]\t\t", pe32.th32ProcessID);
            printf("%s\n", pe32.szExeFile);
            bRet = Process32Next(hprocess, &pe32);
        }
        return true;
}

int main() {
    reversePid();
    return 0;
}
