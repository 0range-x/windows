#include <Windows.h>
#include<stdlib.h>
#include <stdio.h>
#include <assert.h>

DWORD RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva);
void getExportTable(LPVOID pFileBuffer);
void getRelocationTable(LPVOID pFileBuffer);
//size�ǵ�ַ��ALIGN_BASE �ǰ���ʲô����
DWORD Align(DWORD size, DWORD ALIGN_BASE);