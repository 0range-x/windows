#include <Windows.h>
#include<stdlib.h>
#include <stdio.h>
#include <assert.h>

DWORD RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva);
void getExportTable(LPVOID pFileBuffer);
void getRelocationTable(LPVOID pFileBuffer);
//size是地址，ALIGN_BASE 是按照什么对齐
DWORD Align(DWORD size, DWORD ALIGN_BASE);