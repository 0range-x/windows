#pragma once
#include<Windows.h>
#include<stdio.h>
#include<stdlib.h>
#include<TlHelp32.h>
#include<iostream>
#include<winternl.h>
#include<Psapi.h>


typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

HANDLE GetProcessHandle(int nID);
BOOL reflectiveLoader(LPCSTR dllPath);
using DLLEntry = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);