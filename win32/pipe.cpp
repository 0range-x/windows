#include<Windows.h>
#include<stdio.h>

BOOL PipeCmd(char* pszCmd, char* pszResultBuffer, DWORD dwResultBufferSize) {
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE hReadPipe = NULL;
	HANDLE hWritePipe = NULL;
	BOOL bRet = FALSE;
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	//设定管道的安全属性
	sa.bInheritHandle = TRUE;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;

	//创建管道
	bRet = CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
	if (FALSE == bRet) {
		printf("[-] CreatePipe Error:%d", GetLastError());
		exit(-1);
	}

	//设置新进程参数
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdError = hWritePipe;
	si.hStdOutput = hWritePipe;

	//创建进程执行命令并将结果写进匿名管道
	bRet = CreateProcess(NULL, pszCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	if (FALSE == bRet) {
		printf("[-] CreatePipe Error:%d", GetLastError());
		exit(-1);
	}

	//等待命令执行结束
	WaitForSingleObject(pi.hThread, INFINITE);
	WaitForSingleObject(pi.hProcess, INFINITE);

	//从管道读取结果输出到缓冲区
	RtlZeroMemory(pszResultBuffer, dwResultBufferSize);
	ReadFile(hReadPipe, pszResultBuffer, dwResultBufferSize, NULL, NULL);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(hWritePipe);
	CloseHandle(hReadPipe);
	return true;
}

int main(int argc, char* argv[]) {
	char szCmd[] = "whoami";
	char szResultBuffer[512] = { 0 };
	DWORD dwResultBufferSize = 512;

	if (FALSE == PipeCmd(szCmd, szResultBuffer, dwResultBufferSize)) {
		printf("[-]PipeCmd Error.\n");
		exit(-1);
	}
	else
	{
		printf("[+] Result:\n%s\n", szResultBuffer);
	}
}