#include<Windows.h>
#include<stdio.h>

BOOL PipeCmd(char* pszCmd, char* pszResultBuffer, DWORD dwResultBufferSize) {
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE hReadPipe = NULL;
	HANDLE hWritePipe = NULL;
	BOOL bRet = FALSE;
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	//�趨�ܵ��İ�ȫ����
	sa.bInheritHandle = TRUE;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;

	//�����ܵ�
	bRet = CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
	if (FALSE == bRet) {
		printf("[-] CreatePipe Error:%d", GetLastError());
		exit(-1);
	}

	//�����½��̲���
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdError = hWritePipe;
	si.hStdOutput = hWritePipe;

	//��������ִ����������д�������ܵ�
	bRet = CreateProcess(NULL, pszCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	if (FALSE == bRet) {
		printf("[-] CreatePipe Error:%d", GetLastError());
		exit(-1);
	}

	//�ȴ�����ִ�н���
	WaitForSingleObject(pi.hThread, INFINITE);
	WaitForSingleObject(pi.hProcess, INFINITE);

	//�ӹܵ���ȡ��������������
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