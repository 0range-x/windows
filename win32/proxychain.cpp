#include<Windows.h>
#include"prchauto.h"
#include<stdio.h> 

//定义com组件使用的bool值
typedef short VARIANT_BOOL;
#define VARIANT_TRUE ((VARIANT_BOOL)-1)
#define VARIANT_FALSE ((VARIANT_BOOL)0)

#define CLSID_ProcessChain L"{E430E93D-09A9-4DC5-80E3-CBB2FB9AF28E}"
#define IID_IProcessChain  L"{79ED9CB4-3A01-4ABA-AD3C-A985EE298B20}"

BOOL ProcessChain(wchar_t cmd[]) {
	HRESULT hr = 0;
	CLSID clsidIProcessChain = { 0 };
	IID iidIProcessChain = { 0 };
	IProcessChain* ProcessChain = NULL;
	BOOL bRet = FALSE;

	//初始化com环境
	CoInitialize(NULL);

	CLSIDFromString(CLSID_ProcessChain, &clsidIProcessChain);
	IIDFromString(IID_IProcessChain, &iidIProcessChain);

	//创建com接口
	hr = CoCreateInstance(clsidIProcessChain, NULL, CLSCTX_INPROC_SERVER, iidIProcessChain, (LPVOID*)&ProcessChain);
	
    //设置布尔值供start接受参数
	VARIANT_BOOL vb = VARIANT_TRUE;

	//设置参数
	ProcessChain->put_CommandLine((BSTR)cmd);

	//调用方法
	hr = ProcessChain->Start(&vb);
	printf("[+] Load successfully!");
	//释放
	CoUninitialize();
	return TRUE;
}

int main() {
	wchar_t cmd[] = L"C:\\windows\\system32\\calc.exe";
	ProcessChain(cmd);
	return 0;
}