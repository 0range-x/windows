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

	//构造搜索文件类型字符串，*.*表示搜索所有文件类型
	wsprintf(pszFileName, "%s\\*.*", pszDirectory);

	HANDLE hFile = FindFirstFile(pszFileName, &FileData);
	if (INVALID_HANDLE_VALUE != hFile) {
		do {
			//过滤掉当前目录和上一层目录，否则会进入死循环
			if ('.' == FileData.cFileName[0])  continue;
			//拼接文件路径
			wsprintf(pTempSrc, "%s\\%s", pszDirectory, FileData.cFileName);
			//判断目录还是文件
			if (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				SearchFile(pTempSrc);		//递归遍历
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