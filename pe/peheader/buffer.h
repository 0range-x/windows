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

							
//��ȡʧ�ܷ���0  ���򷵻�ʵ�ʶ�ȡ�Ĵ�С								
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer);


//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С													
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);

//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С													
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);

//��ȡʧ�ܷ���false  ���򷵻�true													
BOOL AddImageBufferToShellCode(IN OUT LPVOID pImageBuffer, IN const char* pShellCode, IN size_t pShellCodeSize);

//**************************************************************************								
//EnlargedNodalRegion:�������
//����˵����								
//pFileBuffer FileBufferָ��								
//pNewBuffer NewBufferָ��
//EnlargeSize ��������Ĵ�С
//����ֵ˵����								
//��ȡʧ�ܷ���false  ���򷵻�true							
//**************************************************************************		
BOOL EnlargedNodalRegion(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer, size_t EnlargeSize);


//**************************************************************************								
//EnlargedNodalRegion:�ϲ�����
//����˵����								
//pFileBuffer FileBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���false  ���򷵻�true							
//**************************************************************************		
BOOL MergingSection(IN OUT LPVOID* pImageBuffer);

								
//MemeryTOFile:���ڴ��е����ݸ��Ƶ��ļ�								
BOOL MemeryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile);

							
DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva);

//**************************************************************************								
//AddImageBufferToShellCode:��FileBuffer����ӽڱ�						
//����˵����								
//pFileBuffer �ļ�ָ��								
//pNewBuffer ���ļ�ָ��
//sectionTable ��ӽڱ���
//SsectionTableSize ��ӽڱ��С
//����ֵ˵����								
//���ʧ�ܷ���false  ���򷵻�true							
//**************************************************************************	
BOOL AddFileBufferToSectionTable(IN LPVOID pFileBuffer, OUT LPVOID* pNewBuffer, IN const char* sectionTable, IN size_t SsectionTableSize);

//**************************************************************************								
//DeleteDarbageDataUnderDOS:ɾ��Dosͷ�±����������������ݣ������ڱ�λ��			
//����˵����								
//*pFileBuffer �ļ�ָ��								
//����ֵ˵����								
//���ʧ�ܷ���false  ���򷵻�true							
//**************************************************************************	
BOOL DeleteDarbageDataUnderDOS(IN OUT LPVOID* pFileBuffer);

//**************************************************************************	
//**************************************************************************	
//**************************************************************************	
//�·�Ϊ���Դ���
//**************************************************************************	
//**************************************************************************	
//**************************************************************************	

//**************************************************************************								
//PrintPEHeaders:��ӡ�ڱ���Ϣ				
//����˵����								
//LPVOID* pFileBuffer ָ��																
//����ֵ˵����								
//��							
//**************************************************************************		
void PrintPEHeaders(LPVOID* pFileBuffer);

//**************************************************************************								
//PrintPEHeaders:�ַ�ѹ�����ڴ�	
//����˵����								
//const char* shellCode ָ��			
//size_t shellCodeSize	ָ��
//char* pFileState		ָ��
//����ֵ˵����								
//��							
//**************************************************************************		
void AddCharacterCompressionToMemory(IN const char* shellCode, size_t shellCodeSize, OUT char* pFileState);


#include <assert.h>
//��������: ��ALIGN_BASEΪ����ȶ���size
//����˵��: 
//		size:��Ҫ����Ĵ�С
//		ALIGN_BASE:�����
//����ֵ:	���ض����Ĵ�С
DWORD Align(DWORD size, DWORD ALIGN_BASE);
