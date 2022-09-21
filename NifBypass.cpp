// NIFBYPASS1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include "string"
#include "iostream"
#include <stdio.h>
#include <TlHelp32.h>
#include <psapi.h>

using namespace std;

#pragma comment( lib, "psapi" )


DWORD pid;

enum THREADINFOCLASS
{
    ThreadQuerySetWin32StartAddress = 9,
};
 
typedef NTSTATUS(__stdcall * f_NtQueryInformationThread)(HANDLE, THREADINFOCLASS, void*, ULONG_PTR, ULONG_PTR*);

ULONG_PTR GetThreadStartAddress(HANDLE hThread)
{
    auto NtQueryInformationThread = reinterpret_cast<f_NtQueryInformationThread>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"));
    if (!NtQueryInformationThread)
        return 0;
 
    ULONG_PTR ulStartAddress = 0;
    NTSTATUS Ret = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &ulStartAddress, sizeof(ULONG_PTR), nullptr);
 
    if (Ret)
        return 0;
 
    return ulStartAddress;
}

bool TerminateThreadByStartaddress(ULONG_PTR StartAddress, DWORD dwProcId)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (!hSnap)
        return false;
 
    THREADENTRY32 TE32 = { 0 };
    TE32.dwSize = sizeof(THREADENTRY32);
 
    BOOL Ret = Thread32First(hSnap, &TE32);
    while (Ret)
    {
        if (TE32.th32OwnerProcessID == dwProcId)
        {
            HANDLE hTempThread = OpenThread(THREAD_ALL_ACCESS, FALSE, TE32.th32ThreadID);
            if (!hTempThread)
                continue;
 
            if (StartAddress == GetThreadStartAddress(hTempThread))
            {
                TerminateThread(hTempThread, 0);
                CloseHandle(hTempThread);
                CloseHandle(hSnap);
                return true;
            }
        }
        Ret = Thread32Next(hSnap, &TE32);
    }
 
    CloseHandle(hSnap);
 
    return false;
}

DWORD dwGetModuleBaseAddress(DWORD dwProcessIdentifier, TCHAR *lpszModuleName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessIdentifier);
    DWORD dwModuleBaseAddress = 0;
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 ModuleEntry32 = { 0 };
        ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &ModuleEntry32))
        {
            do
            {
                if (strcmp(ModuleEntry32.szModule, lpszModuleName) == 0)
                {
                    dwModuleBaseAddress = (DWORD)ModuleEntry32.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnapshot, &ModuleEntry32));
        }
        CloseHandle(hSnapshot);
    }
    return dwModuleBaseAddress;
}
 

int main()
{
	HWND tabiaWindow;
	HANDLE hProcess;
	char szBuffer[1024];
	system("title NifBypass By Noob");
	HWND hWnd = FindWindowA(0, ("BlackShot"));
	GetWindowThreadProcessId(hWnd, &pid);
	if (hWnd)
	{
		cout << "Process Found [OK]\n";
		cout << pid << endl;
		system("color 4B");
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		DWORD base = dwGetModuleBaseAddress(pid, "calc.exe");
		TerminateThreadByStartaddress(base+ 0x2551 + 0x7095e8, pid)s;
		sprintf(szBuffer, "Terminate Thread Address ", base + 0x7095e8);
		cout << szBuffer << endl;
		cout << "Coded By mushNn : wHizzz#0001" << endl;
		Console.WriteLine(Bypass.NIF.Blackshot, 0x7095e8):
	}
	else
	{
		cout << "Window Not Found";
		system("color 4B");
	}
	Sleep(9999);
}

