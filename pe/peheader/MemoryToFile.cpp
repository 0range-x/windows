#include "buffer.h"

BOOL MemeryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile)
{
	FILE* pFlieStream = NULL;
	unsigned int fileSize = 0;
	if ((pFlieStream = fopen(lpszFile, "wb")) == NULL)
	{
		printf("�ļ���ʧ�ܣ�����·����");
		return false;
	}
	int ret = fwrite(pMemBuffer, sizeof(char), size, pFlieStream);
	if (ret = size)
		return	true;
	return false;
}