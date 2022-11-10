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

	//��ȡ�����Ϣ
	GetCursorInfo(&ci);
	//��ȡͼ����Ϣ
	GetIconInfo(ci.hCursor, &ii);
	//���ư׵׺����
	HBITMAP hOldMask = NULL;
	hOldMask = (HBITMAP)SelectObject(bufDc, ii.hbmMask);
	BitBlt(hdc, ci.ptScreenPos.x, ci.ptScreenPos.y, 20, 20, bufDc, 0, 0, SRCAND);
	//���ƺڵײ�ɫ���
	SelectObject(bufDc, ii.hbmColor);
	BitBlt(hdc, ci.ptScreenPos.x, ci.ptScreenPos.y, 20, 20, bufDc, 0, 0, SRCPAINT);

	//�ͷ�
	SelectObject(bufDc, hOldMask);
	DeleteObject(ii.hbmColor);
	DeleteObject(ii.hbmMask);
	DeleteDC(bufDc);
	return TRUE;
}

BOOL ScreenCapture() {
	//��ȡ���洰�ھ��
	
	HWND hDesktopWnd = GetDesktopWindow();
	HDC hDc = GetDC(hDesktopWnd);
	HDC bufDc= CreateCompatibleDC(hDc);
	HBITMAP bmp=NULL;
	HBITMAP holdbmp = NULL;

	//��ȡ�������Ļ�Ŀ�͸�
	DWORD dwScreenWidth = GetSystemMetrics(SM_CXSCREEN);
	DWORD dwSCreenHeight = GetSystemMetrics(SM_CYSCREEN);
	//����������ͼ
	bmp=CreateCompatibleBitmap(hDc, dwScreenWidth, dwSCreenHeight);
	//ѡ��λͼ
	holdbmp = (HBITMAP)SelectObject(bufDc, bmp);
	//���������ݻ��Ƶ�ͼ��
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