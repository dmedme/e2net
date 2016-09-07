/****************************************************************************
 *  PROGRAM: e2nettst.c
 *
 *  PURPOSE: Start the E2 Systems Network Benchmark Control Program.
 *
 ****************************************************************************/
static char * sccs_id = "@(#) $Name$ $Id$\n\
Copyright (c) E2 Systems Limited 1998";
#include <windows.h>            /* required for all Windows applications */
#include <shlobj.h>
#include <shlguid.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "e2nettst.h"
#ifdef JUNK
#ifdef SHGetSpecialFolderPath
#undef SHGetSpecialFolderPath
BOOL _stdcall SHGetSpecialFolderPath(HWND,LPSTR,int,BOOL);
#endif
#endif
/*
 * Linked list of environment settings read from a file
 */
struct env_con {
    struct env_con * next;
    char *vl;
    char nm[1];
};
static struct env_con * env_anchor; 
static void read_config();
static void write_config();
static void env_note();
static void env_replace();
static void env_update();
static char * env_value();
static HRESULT CreateLink(LPCSTR lpszPathObj, LPSTR lpszPathLink,
          LPSTR lpszDesc);
static void e2sync_start();

int APIENTRY WinMain(HINSTANCE,HINSTANCE,LPSTR,int);
static BOOL InitApplication(void);
HANDLE hAccelTable;                                    /* Accelerator Table */
long CALLBACK  MainWndProc(HWND, UINT, WPARAM, LPARAM);
static HANDLE hInst;          /* Current instance identifier.       */
static HWND hwndMain;         /* Main Window                        */
static char  * egets(char * ptr, int len, FILE  * f);
/****************************************************************************
 *
 *  PURPOSE: puts out a message box, using a format and a numeric and
 *  string argument.
 */
static void ShowError(lpTitle, lpFmt, lpStr, ulNum)
LPSTR lpTitle;
LPSTR lpFmt;
LPSTR lpStr;
LONG ulNum;
{
static int in_here;
char buf[128];

    if (in_here)
        return;
    else
        in_here = 1;
    (void) sprintf( (LPSTR) &buf[0],lpFmt, lpStr, ulNum);
    if (InSendMessage())
        ReplyMessage(TRUE);
    (void) MessageBox((HWND) NULL,
            (LPCSTR) &buf[0], lpTitle,
               MB_TASKMODAL|MB_ICONSTOP|MB_OK|MB_TOPMOST|MB_SETFOREGROUND);
    in_here = 0;
    return;
}
/*******************************************************************************
 * Standard windows flannel
 */
static BOOL InitApplication(void)
{
WNDCLASSEX wc;      /* A window class structure. */
struct stat sbuf;
char this_exe[256];
char desktop[256];

    read_config("pathenv.sh");
    env_update();
#ifdef JUNK
    getcwd(this_exe, sizeof(this_exe));
    strcat(this_exe, "\\e2nettst.exe");
    SHGetSpecialFolderPath(NULL,&desktop[0],CSIDL_DESKTOPDIRECTORY, 0);
    strcat(desktop, "\\e2nettst.exe.lnk");
    if (stat(this_exe,&sbuf) >= 0 && stat(desktop,&sbuf) < 0)
    {
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        CreateLink(this_exe, desktop, "E2 Systems Network Benchmark Tools");
    }
#endif
    if (!GetClassInfoEx(hInst, WC_DIALOG, &wc))
    {
        ShowError("InitApplication",
             "Failed to get DIALOGBOX class information: Error %u",
              GetLastError());
        return FALSE;
    }
/*
 * Change the bits that need to be altered
 */
    wc.lpfnWndProc = (WNDPROC)MainWndProc;
    wc.lpszClassName = "E2NETTST";
    wc.lpszMenuName = MAKEINTRESOURCE(E2NETTSTMENU);
    wc.hInstance = hInst;
    wc.cbSize = sizeof(wc);
    wc.hIcon = LoadIcon(hInst, MAKEINTATOM(IDI_E2NETTST));
/*
 * Now register the window class for use.
 */
    if (!RegisterClassEx (&wc))
    {
        ShowError("e2nettst", 
                       (LPSTR) "Failed to Register Class, Error:%d",
                GetLastError());
        return 0;
    }
    return 1;
}
/*
 * Used for creating a link to the startup program on the desktop
 */
static HRESULT CreateLink(LPCSTR lpszPathObj, LPSTR lpszPathLink,
          LPSTR lpszDesc) 
{ 
HRESULT hres; 
IShellLink* psl; 
/*
 *  Get a pointer to the IShellLink interface.
 */
    hres = CoCreateInstance(&CLSID_ShellLink, NULL, 
        CLSCTX_INPROC_SERVER, &IID_IShellLink, &psl); 
    if (SUCCEEDED(hres))
    { 
    IPersistFile* ppf; 
/*
 * Set the path to the shortcut target and add the description.
 */
        psl->lpVtbl->SetPath(psl, lpszPathObj); 
        psl->lpVtbl->SetDescription(psl, lpszDesc); 
/*
 * Query IShellLink for the IPersistFile interface for saving the shortcut
 * in persistent storage.
 */
        hres = psl->lpVtbl->QueryInterface(psl, &IID_IPersistFile, 
            &ppf); 
        if (SUCCEEDED(hres))
        { 
        WORD wsz[MAX_PATH]; 
/*
 * Ensure that the string is ANSI.
 */
            MultiByteToWideChar(CP_ACP, 0, lpszPathLink, -1, wsz, MAX_PATH); 
/*
 * Save the link by calling IPersistFile::Save.
 */
            hres = ppf->lpVtbl->Save(ppf, wsz, TRUE); 
            ppf->lpVtbl->Release(ppf); 
        } 
        psl->lpVtbl->Release(psl); 
    } 
    return hres; 
} 
/*****************************************************************************
 * The About dialogue
 */
BOOL WINAPI AboutDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch(msg)
    {
        case WM_CLOSE:
            EndDialog(hwnd,0);
            return 1;
        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
            case IDOK:
                EndDialog(hwnd,1);
                return 1;
            }
            break;
    }
    return 0;
}
/*
 * Standard windows event loop
 */
static int do_message_loop()
{
MSG msg;

    while (GetMessage(&msg,NULL,0,0))
    {
        if (!TranslateAccelerator(msg.hwnd,hAccelTable,&msg))
        {
            TranslateMessage(&msg);
#ifdef DEBUG_FULL
        ShowError((LPSTR) "do_message_loop",
                           (LPSTR) "Dispatching Message %u",
                        msg.message);
#endif
            DispatchMessage(&msg);
        }
    }
#ifdef DEBUG_FULL
    ShowError((LPSTR) "do_message_loop",
                       (LPSTR) "Exit Message %u",
                    msg.message);
#endif
    return msg.wParam;
}
/*************************************************************************
 * Table of items, windows and Old Windows Procedures for sub-classing
 */
static struct proc_look {
    HWND hwndCtl;
    WNDPROC OldProc;
} proc_look[14];
/*************************************************************************
 * Procedure to implement tabbing between input fields that normally capture
 * the TAB key.
 */
LRESULT CALLBACK TabProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
int i;
static int shift_seen;

    switch (msg)
    {
    case WM_KEYDOWN:
        if (wParam == VK_SHIFT )
            shift_seen = 1;
        break;
    case WM_COMMAND:
        SendMessage(GetParent(hwnd), msg, wParam, lParam);
        return FALSE;
    case WM_CHAR:
        if (wParam == VK_TAB )
        {
            SetFocus(GetNextDlgTabItem(GetParent(hwnd),
                            hwnd, shift_seen));
            return FALSE;
        }
        else
            break;
    case WM_KEYUP:
        if (wParam == VK_SHIFT )
            shift_seen = 0;
        break;
    }
    for (i = 0; i < 14; i++)
    {
        if (hwnd == proc_look[i].hwndCtl)
            return CallWindowProc((proc_look[i].OldProc),
                            hwnd,msg,wParam,lParam);
    }
    ShowError("e2nettst:TabProc",
              "Logic Error: Did not find window %x", hwnd, 0);
    return FALSE;
}
/****************************************************************************
 * Sub-class a dialogue control to allow it to handle TAB keys as we would
 * like.
 */
void E2EditSubClass(HWND hwndCtl)
{
int i;
    for (i = 0; i < 14; i++)
    {
        if (proc_look[i].hwndCtl == hwndCtl)
            return;
        if (proc_look[i].hwndCtl == (HWND) 0)
        {
            if (TabProc != (WNDPROC) GetWindowLong(hwndCtl, GWL_WNDPROC))
            {
                proc_look[i].OldProc =
                    (WNDPROC) SetWindowLong(hwndCtl, GWL_WNDPROC,
                                      (LONG) TabProc);
                proc_look[i].hwndCtl = hwndCtl;
                return;
            }
        }
    }
    ShowError("e2nettst:E2EditSubClass",
              "Logic Error: Too Many Controls (> 14)", 0, 0);
    return;
}
/*
 * Function to startup the benchmark
 */
static HANDLE bench_start(char * office)
{
char command_line[128];
STARTUPINFO si;
PROCESS_INFORMATION pi;
char * home_host;
char * home_port;

    si.cb = sizeof(si);
    si.lpReserved = NULL;
    si.lpDesktop = NULL;
    si.lpTitle = "E2 Systems Load Test Utility";
    si.dwX = 0;
    si.dwY = 0;
    si.dwXSize = 0;
    si.dwYSize= 0;
    si.dwXCountChars = 0;
    si.dwYCountChars= 0;
    si.dwFillAttribute= 0;
    si.dwFlags = 0;
    si.wShowWindow = 0;
    si.cbReserved2 = 0;
    si.lpReserved2 = NULL;

    if ((home_port = getenv("E2_HOME_PORT")) == (char *) NULL)
        home_port = "5000";
    if ((home_host = getenv("E2_HOME_HOST")) == (char *) NULL)
        home_host = "192.168.0.5";
    sprintf(command_line,
          "minitest %s %s EXEC echo e2nettst started at %s",
               home_host, home_port, office);
    if (!CreateProcess(NULL, command_line, NULL, NULL, TRUE,
                  DETACHED_PROCESS, NULL, NULL, &si, &pi))
        ShowError("e2nettst calling home","minitest failed to run error %d",
                  GetLastError(),0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    sprintf(command_line, "minitest %s", home_port);
    if (!CreateProcess(NULL, command_line, NULL, NULL, TRUE,
                  CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
        ShowError("e2nettst manager startup","minitest failed to run error %d",
                  GetLastError(),0);
    CloseHandle(pi.hThread);
    return pi.hProcess;
}
/*
 * Function to startup the benchmark
 */
static void e2sync_start()
{
char command_line[128];
STARTUPINFO si;
PROCESS_INFORMATION pi;

    si.cb = sizeof(si);
    si.lpReserved = NULL;
    si.lpDesktop = NULL;
    si.lpTitle = "E2 Systems Script Comments";
    si.dwX = 0;
    si.dwY = 0;
    si.dwXSize = 0;
    si.dwYSize= 0;
    si.dwXCountChars = 0;
    si.dwYCountChars= 0;
    si.dwFillAttribute= 0;
    si.dwFlags = 0;
    si.wShowWindow = 0;
    si.cbReserved2 = 0;
    si.lpReserved2 = NULL;

    strcpy(command_line, "e2sync");
    if (!CreateProcess(NULL, command_line, NULL, NULL, TRUE,
                  DETACHED_PROCESS, NULL, NULL, &si, &pi))
        ShowError("e2nettst calling home","e2sync failed to run error %d",
                  GetLastError(),0);
    CloseHandle( pi.hProcess);
    CloseHandle( pi.hThread);
    return;
}
/****************************************************************************
    FUNCTION: MainWndProc(HWND, UINT, WPARAM, LPARAM)

    PURPOSE:  Processes messages

    MESSAGES:

    WM_DESTROY    - destroy window
****************************************************************************/

long CALLBACK  MainWndProc(hWnd, message, wParam, lParam)
HWND hWnd;                      /* window handle                 */
UINT message;                   /* type of message               */
WPARAM wParam;                  /* additional information        */
LPARAM lParam;                  /* additional information        */
{
    switch (message)
    {
    case WM_DESTROY:
/*
 * Close any log file
 */
        PostQuitMessage(0);
        break;
    default:
        return DefDlgProc(hWnd,message,wParam,lParam);
    }
    return 0;
}
/*
 * Handle the startup button
 */
BOOL  CALLBACK Comment(hDlg, message, wParam, lParam)
HWND hDlg;               /* window handle of the dialog box */
UINT message;        /* type of message                 */
WPARAM wParam;             /* message-specific information    */
LPARAM lParam;
{
UINT uiMsg;
HWND hwndCtl;
WORD id;
int ret;
static HWND hStatus;
static HANDLE bench_child;
HCURSOR hPrev, hHour;
RECT rc;
static char office[256];
char *x;

    hHour = LoadCursor(NULL, IDC_WAIT);
    switch (message)
    {
    case WM_INITDIALOG:            /* message: initialize dialog box */
        E2EditSubClass(GetDlgItem(hDlg, IDOK));
        E2EditSubClass(GetDlgItem(hDlg, IDC_REMARKS));
        if ((x = env_value("E2_CLIENT_LOCATION")) != (char *) NULL)
        {
            strcpy(office, x);
            SetWindowText(GetDlgItem(hDlg, IDC_REMARKS), office);
        }
        (void) GetWindowRect(hDlg,(RECT  *) &rc);
        (void) SetWindowPos(hDlg,HWND_TOPMOST,rc.left,rc.top,
                     rc.right - rc.left, rc.bottom - rc.top,
                         SWP_SHOWWINDOW);
        hStatus = CreateStatusWindow(WS_CHILD|WS_VISIBLE,
                  "No Benchmark control process running", hDlg, IDW_STATUS);
        return (TRUE);
    case WM_COMMAND:               /* message: received a command */
        uiMsg = HIWORD(wParam);
        hwndCtl = (HWND) lParam;
        id = LOWORD(wParam);
        switch(id)
        {
        case IDOK:                 /* "OK" box selected?          */
            if (!GetExitCodeProcess( bench_child, &ret)
              || ret != STILL_ACTIVE)
            {
                GetWindowText( GetDlgItem(hDlg, IDC_REMARKS), 
                       &office[0], sizeof(office));
                if (env_anchor == (struct env_con *) NULL)
                    read_config("pathenv.sh");
                if (((x = env_value("E2_CLIENT_LOCATION")) == (char *) NULL)
                      || strcmp(x, office))
                {
                    env_replace("E2_CLIENT_LOCATION",office);
                    write_config("pathenv.sh");
                    env_update();
                }
                hPrev = GetCursor();
                SetCursor(hHour);
                SetWindowText(hStatus, "Starting Benchmark Controller");
                bench_child = bench_start(office); 
                if (!GetExitCodeProcess( bench_child, &ret)
                  || ret != STILL_ACTIVE)
                    SetWindowText(hStatus,
                           "No Benchmark control process running");
                else
                    SetWindowText(hStatus,
                           "Benchmark control process running");
                SetCursor(hPrev);
            }
            break;
        case IDM_ABOUT:
            (void) DialogBox(hInst,MAKEINTRESOURCE(IDD_ABOUT),
                    hDlg,AboutDlg);
            return (TRUE);
        case ID_SCRIPT:
            (void) e2sync_start();
            return (TRUE);
    
        case ID_EXIT:
        case IDCANCEL:
            EndDialog(hDlg, FALSE);
            PostQuitMessage(TRUE);
            break;
        default:
             break;
        }
        break;
    }
    return (FALSE);                    /* Didn't process a message    */
}
/****************************************************************************
 * Main program starts here
 *
 *  FUNCTION: WinMain(HANDLE, HANDLE, LPSTR, int)
 *
 *  COMMENTS:
 *      Windows recognizes this function by name as the initial entry point
 *      for the program.  This function calls the application initialization
 *      routine, if no other instance of the program is running, and always
 *      calls the instance initialization routine.  It then executes a message
 *      retrieval and dispatch loop that is the top-level control structure
 *      for the remainder of execution.  The loop is terminated when a WM_QUIT
 *      message is received, at which time this function exits the application
 *      instance by returning the value passed by PostQuitMessage().
 *
 *      If this function must abort before entering the message loop, it
 *      returns the conventional value 0.
 * VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
 * Entry point - Main Program Start Here
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                LPSTR lpCmdLine, INT nCmdShow)
{
    hAccelTable = LoadAccelerators(hInst,MAKEINTRESOURCE(IDACCEL));
    hInst = hInstance;
    InitCommonControls(); 
    if (!InitApplication())
    {
        return 0;
    }
    if ((hwndMain = CreateDialogParam(hInstance,
                MAKEINTRESOURCE(E2NETTSTBOX), NULL, Comment, 0L ))
            == NULL)
    {
        ShowError((LPSTR) "e2nettst.exe",
         (LPSTR) "CreateDialogParam Failed, Error %u", GetLastError());
        return 0;
    }
    else
    {
        ShowWindow(hwndMain, nCmdShow);
        ShowWindow(hwndMain, SW_SHOW);
        return do_message_loop();
    }
}
static void env_note(n, v)
char *n;
char *v;
{
int vl;
int nl;
struct env_con * tp;

    if (n != (char *) NULL && v != (char *) NULL)
    {
        nl = strlen(n);
        vl = strlen(v);
        if ((tp = (struct env_con *)
               malloc(sizeof(struct env_con) + nl + vl + 1))
                           != (struct env_con *) NULL)
        {
            tp->next = env_anchor;
            strcpy(&(tp->nm[0]), n);
            tp->vl = &(tp->nm[nl + 1]);
            strcpy(tp->vl, v);
            env_anchor = tp;
        }
    }
    return;
}
/*
 * Put the environment values into the environment; unhook them from the list
 * as they go, to avoid accidently freeing them.
 */
static void env_update()
{
struct env_con * tp;

    while (env_anchor != (struct env_con *) NULL)
    {
        tp = env_anchor;
        tp->nm[strlen(tp->nm)] = '=';
        putenv(&(tp->nm[0]));
        env_anchor = tp->next;
    }
    return;
}
/*
 * Put the environment values into the environment; unhook them from the list
 * as we go, to avoid accidently freeing them.
 */
static void env_replace(n,v)
char * n;
char * v;
{
struct env_con * tp, *tp1;

    for (tp = (struct env_con *) NULL,
         tp1 = env_anchor;
               tp1 != (struct env_con *) NULL;
                   tp = tp1,
                   tp1 = tp1->next)
    {
        if (!strcmp(n, tp1->nm))
        {
            if (tp == (struct env_con *) NULL)
                env_anchor = tp1->next;
            else
                tp->next = tp1->next;
            free((char *) tp1);
            break;
        }
    }
    env_note(n,v);
    return;
}
/*
 * Find an environment value in the environment.
 */
static char * env_value(n)
char * n;
{
struct env_con * tp;

    for ( tp = env_anchor;
               tp != (struct env_con *) NULL;
                   tp = tp->next)
    {
        if (!strcmp(n, tp->nm))
            return tp->vl;
    }
    return (char *) NULL;
}
static void env_zap()
{
struct env_con * tp;

    while (env_anchor != (struct env_con *) NULL)
    {
        tp = env_anchor;
        env_anchor = tp->next;
        free((char *) tp);
    }
    return;
}
/*
 * Just to tidy things up; long shell commands can be part of a single
 * menu option, if a trailing \ is provided
 */
static char  * egets(ptr, len, f)
char  * ptr;
int len;
FILE  * f;
{
char  * w;
char  * r;
int to_do;
int linelen;

    for (w = ptr, r = w, to_do = len;
            to_do > 0 && r != (char *) NULL;)
    {
        r = fgets (w, to_do, f);
        if (r == (char *) NULL)
        {
            if (w == ptr)
                return r;
            else
                return ptr;
        }
        linelen = strlen(r);
        w = w + linelen - 2;
        if (w >= ptr && *w == '\r')
        {
            w--;
            to_do--;
        }
        if (w >= ptr && *w == '\\')
        {
            *w++ = '\n';
            to_do = to_do - linelen - 1;
        }
        else
        {
            w++;
            *w = '\0';
            break;
        }
    }
    return ptr;
}
/*
 * Remove wrapping quotation marks and escapes, UNIX Shell style
 */
static void strip_quotes(raw_string)
char * raw_string;
{
char * bound = raw_string + strlen(raw_string);
char * x;
char nc;
int l;
char * op;
char quote = '\0';

    for ( x = raw_string,
          op = raw_string;
              x < bound;)
    {
        switch(*x)
        {
        case '"':
            if (quote == 0)
            {
                quote = '"';
                x++;
            }
            else
            if (quote == '"')
            {
                quote = 0;
                x++;
            }
            else
                *op++ = *x++;
            break;
        case '\'':
            if (quote == 0)
            {
                quote = '\'';
                x++;
            }
            else
            if (quote == '\'')
            {
                quote = 0;
                x++;
            }
            else
                *op++ = *x++;
            break;
        case '\\':
            if (quote == 0)
                x++;
            else
            if (quote == '"')
            {
                nc = *(x + 1);
                if (nc == '"' || nc == '$' || nc == '\\')
                    x++;
            }
        default:
            if (x == op)
            {
                x++;
                op++;
            }
            else
                *op++ = *x++;
              
            break;
        }
    }
    if (op < bound)
       *op = '\0';
    return;
}
/*
 * Read in a set of environment variable definitions
 */
static void read_config(fname)
char * fname;
{
FILE * fp;
char line_buf[4096];
/*
 * Loop through the strings that are fed on the stream until
 * no more, stuffing them in a control structure
 */
    if ((fp = fopen(fname,"rb")) == (FILE *) NULL)
    {
        ShowError("e2nettst", "Failed to open configuration file %s error %d",
                       fname, GetLastError());
        return;
    }
    while ( egets(line_buf,sizeof(line_buf),fp) != (char *) NULL ) 
    {
    char * n;
    char * v;

        n = strtok(line_buf,"=");
        if ( n == (char *) NULL  || *n == '#')
            continue;
        v = strtok(NULL,"\n\r");
        if (v != (char *) NULL)
        {
            strip_quotes(v);
            env_replace(n, v);
        }
    }
    (void) fclose(fp);
    return;
}
/*
 * Write out a set of environment variable definitions
 */
static void write_config(fname)
char * fname;
{
FILE * fp;
char line_buf[4096];
struct env_con * tp;
/*
 * Loop writing out environment variables to a configuration file
 */
    if ((fp = fopen(fname,"wb")) == (FILE *) NULL)
        ShowError("e2nettst", "Failed to open configuration file %s error %d",
                       fname, GetLastError());
    for (tp = env_anchor; tp != (struct env_con *) NULL;tp = tp->next)
         fprintf(fp, "%s=\"%s\"\n", tp->nm, tp->vl);
    (void) fclose(fp);
    return;
}
