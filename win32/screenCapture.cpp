#include<Windows.h>
#include<atlimage.h>


BOOL SaveBmp(HBITMAP hBmp) {
	CImage image;
	image.Attach(hBmp);
	image.Save("screen.jpg");
	return true;
}

BOOL PaintMouse(HDC hdc) {
	CURSORINFO ci = { 0 };
	ICONINFO ii = { 0 };
	RtlZeroMemory(&ii, sizeof(ii));
	ci.cbSize = sizeof(ci);
	HDC bufDc =NULL;

	//获取光标信息
	GetCursorInfo(&ci);
	//获取图标信息
	GetIconInfo(ci.hCursor, &ii);
	//绘制白底黑鼠标
	HBITMAP hOldMask = NULL;
	hOldMask = (HBITMAP)SelectObject(bufDc, ii.hbmMask);
	BitBlt(hdc, ci.ptScreenPos.x, ci.ptScreenPos.y, 20, 20, bufDc, 0, 0, SRCAND);
	//绘制黑底彩色鼠标
	SelectObject(bufDc, ii.hbmColor);
	BitBlt(hdc, ci.ptScreenPos.x, ci.ptScreenPos.y, 20, 20, bufDc, 0, 0, SRCPAINT);

	//释放
	SelectObject(bufDc, hOldMask);
	DeleteObject(ii.hbmColor);
	DeleteObject(ii.hbmMask);
	DeleteDC(bufDc);
	return TRUE;
}

BOOL ScreenCapture() {
	//获取桌面窗口句柄
	
	HWND hDesktopWnd = GetDesktopWindow();
	HDC hDc = GetDC(hDesktopWnd);
	HDC bufDc= CreateCompatibleDC(hDc);
	HBITMAP bmp=NULL;
	HBITMAP holdbmp = NULL;

	//获取计算机屏幕的宽和高
	DWORD dwScreenWidth = GetSystemMetrics(SM_CXSCREEN);
	DWORD dwSCreenHeight = GetSystemMetrics(SM_CYSCREEN);
	//创建兼容视图
	bmp=CreateCompatibleBitmap(hDc, dwScreenWidth, dwSCreenHeight);
	//选中位图
	holdbmp = (HBITMAP)SelectObject(bufDc, bmp);
	//将窗口内容绘制到图上
	BitBlt(bufDc, 0, 0, dwScreenWidth, dwSCreenHeight, hDc, 0, 0, SRCCOPY);

	PaintMouse(bufDc);
	SaveBmp(bmp);
	return true;
	
}

int main(int argc, char* argv[]) {
	if (FALSE == ScreenCapture()) {
		printf("[-] Failed to screencapture");
		exit(-1);
	}
	printf("[+]ScreenCapture successfully");
	return 0;
}