#ifndef E2NETTST_H
#define E2NETTST_H
/*
 * Used by E2NETTST.RC
 */
#define	IDI_E2NETTST	100
#define	ID_EXIT	101
#define	ID_SCRIPT	113
#define	IDD_DIALOG1	103
#define	IDM_ABOUT	104
#define	IDACCEL	105
#define	IDD_ABOUT	106
#define	E2NETTSTBOX	107
#define	E2NETTSTMENU	108
#define	IDW_STATUS	109
#define	IDC_BOX_1	110
#define	IDC_STATIC_1	111
#define	IDC_STATIC_2	112
#define	IDC_REMARKS	1001

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int);
long CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK About(HWND, unsigned, WPARAM, LPARAM);
#endif
