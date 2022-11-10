#include<Windows.h>
#include<stdio.h>

BOOL SearchFile(char* pszDirectory) {
	DWORD dwBufferSize = 2048;
	char* pszFileName = NULL;
	char* pTempSrc = NULL;
	WIN32_FIND_DATA FileData = { 0 };
	BOOL bRet = FALSE;

	pszFileName = new char[dwBufferSize];
	pTempSrc = new char[dwBufferSize];

	//���������ļ������ַ�����*.*��ʾ���������ļ�����
	wsprintf(pszFileName, "%s\\*.*", pszDirectory);

	HANDLE hFile = FindFirstFile(pszFileName, &FileData);
	if (INVALID_HANDLE_VALUE != hFile) {
		do {
			//���˵���ǰĿ¼����һ��Ŀ¼������������ѭ��
			if ('.' == FileData.cFileName[0])  continue;
			//ƴ���ļ�·��
			wsprintf(pTempSrc, "%s\\%s", pszDirectory, FileData.cFileName);
			//�ж�Ŀ¼�����ļ�
			if (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				SearchFile(pTempSrc);		//�ݹ����
			else
			{
				printf("%s\n", pTempSrc);
			}
		} while (FindNextFile(hFile, &FileData));
	}FindClose(hFile);
	delete[]pTempSrc;
	pTempSrc = NULL;
	delete[]pszFileName;
	pszFileName = NULL;
	return TRUE;
}

int main(int argc, char* argv[]) {
	if (argc != 2)
	{
		printf("[+] Usage:SearchFile.exe C:\\windows\\system32");
	}
	SearchFile(argv[1]);
	return 0;
}