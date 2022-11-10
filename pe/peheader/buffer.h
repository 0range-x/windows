#pragma once
#include <windows.h>
#include <iostream>

#define MESSAGEBOXADDR 0x75031060
#define FILEPATH_IN "E:\\pe.exe"
#define FILEPATH_OUT "E:\\ca.exe"
#define SHELLCODELENGTH 0x12

BYTE shellCode[] = {
	0x6A,0x00,0x6A,0x00,0x6A,0x00,0x6A,0x00,
	0xE8,0x00,0x00,0x00,0x00,
	0xE9,0x00,0x00,0x00,0x00
};

							
//读取失败返回0  否则返回实际读取的大小								
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer);


//读取失败返回0  否则返回复制的大小													
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);

//读取失败返回0  否则返回复制的大小													
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);

//读取失败返回false  否则返回true													
BOOL AddImageBufferToShellCode(IN OUT LPVOID pImageBuffer, IN const char* pShellCode, IN size_t pShellCodeSize);

//**************************************************************************								
//EnlargedNodalRegion:扩大节区
//参数说明：								
//pFileBuffer FileBuffer指针								
//pNewBuffer NewBuffer指针
//EnlargeSize 扩大节区的大小
//返回值说明：								
//读取失败返回false  否则返回true							
//**************************************************************************		
BOOL EnlargedNodalRegion(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer, size_t EnlargeSize);


//**************************************************************************								
//EnlargedNodalRegion:合并节区
//参数说明：								
//pFileBuffer FileBuffer指针								
//返回值说明：								
//读取失败返回false  否则返回true							
//**************************************************************************		
BOOL MergingSection(IN OUT LPVOID* pImageBuffer);

								
//MemeryTOFile:将内存中的数据复制到文件								
BOOL MemeryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile);

							
DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva);

//**************************************************************************								
//AddImageBufferToShellCode:将FileBuffer中添加节表						
//参数说明：								
//pFileBuffer 文件指针								
//pNewBuffer 新文件指针
//sectionTable 添加节表名
//SsectionTableSize 添加节表大小
//返回值说明：								
//添加失败返回false  否则返回true							
//**************************************************************************	
BOOL AddFileBufferToSectionTable(IN LPVOID pFileBuffer, OUT LPVOID* pNewBuffer, IN const char* sectionTable, IN size_t SsectionTableSize);

//**************************************************************************								
//DeleteDarbageDataUnderDOS:删除Dos头下编译器产生垃圾数据，提升节表位置			
//参数说明：								
//*pFileBuffer 文件指针								
//返回值说明：								
//添加失败返回false  否则返回true							
//**************************************************************************	
BOOL DeleteDarbageDataUnderDOS(IN OUT LPVOID* pFileBuffer);

//**************************************************************************	
//**************************************************************************	
//**************************************************************************	
//下方为测试代码
//**************************************************************************	
//**************************************************************************	
//**************************************************************************	

//**************************************************************************								
//PrintPEHeaders:打印节表信息				
//参数说明：								
//LPVOID* pFileBuffer 指针																
//返回值说明：								
//无							
//**************************************************************************		
void PrintPEHeaders(LPVOID* pFileBuffer);

//**************************************************************************								
//PrintPEHeaders:字符压缩到内存	
//参数说明：								
//const char* shellCode 指针			
//size_t shellCodeSize	指针
//char* pFileState		指针
//返回值说明：								
//无							
//**************************************************************************		
void AddCharacterCompressionToMemory(IN const char* shellCode, size_t shellCodeSize, OUT char* pFileState);


#include <assert.h>
//函数功能: 以ALIGN_BASE为对齐度对齐size
//参数说明: 
//		size:需要对齐的大小
//		ALIGN_BASE:对齐度
//返回值:	返回对齐后的大小
DWORD Align(DWORD size, DWORD ALIGN_BASE);
