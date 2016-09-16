// https://github.com/nemesisqp/al-khaser/blob/master/DebuggerDetection.cpp
// http://www.symantec.com/connect/articles/windows-anti-debug-reference

/******************************************************************************
*                                                                            *
*                                                                            *
*                                                                            *
*                                                                            *
*                                                                            *
*                                                                            *
*                                                                            *
*                                                                            *
*                                                                            *
*                                                                            *
*                                                                            *
******************************************************************************/

/*
Anti-sandboxing
- extended sleeping
- checking for inline hooks on API
- user interaction
- mouse events
- artefact checks
- stalling code (executing useless instructions to
emulate process execution

*/

#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <winternl.h>
#include <VersionHelpers.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winsvc.h>

#pragma comment(lib, "Advapi32.lib")

#include "main.h"
#include "anti.h"
#include "helper.h"

/* Debuggers and Monitors */
LPCSTR DebuggerNames[] = {
	"odbg",
	"ollydbg",
	"ida",
	"immunity",
	"softice",
	"radare",
	"gdb"
	/* needs more names */
};

LPCSTR MonitoringToolNames[] = {
	"procmon",
	"processhacker",
	"procexp",
	"wireshark"
	/* needs more names */
};

/* Artefacts for virtualization */
LPCSTR VMRegistryKeys[] = {
	//"SOFTWARE",						/* check for VMware Inc.*/
	"SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S",
	"SYSTEM\\CurrentControlSet\\CriticalDeviceDatabase\\root#vmwvmchihostdev",
	"SYSTEM\\CurrentControlSet\\Control\\VirtualDeviceDrivers"
};

LPCSTR VMWindowNames[] = {
	/* VMware */
	"vmdisplaychangecontrolclass",
	"vmwaredragdetwndclass",
	"vmtoolsdcontrolwndclass",
	"vmwaretrayicon"
};

LPCSTR VMProcessNames[] = {
	/* VMware */
	"vmtoolsd",
	"vmwaretrat",
	"vmwareuser",
	"vmacthlp",
	/* Virtual Box */
	"vboxservice",
	"vboxtray"
};

LPCSTR VMSys32FileNames[] = {
	/* VMware */
	"driversvmhgfs.dll", // confirm this
	"vm3dgl.dll",
	"vmdum.dll",
	"vm3dver.dll",
	"vmtray.dll",
	"vmtoolshook.dll",
	"vmmousever.dll",
	"vmhgfs.dll",
	"vmguestlibjava.dll",
	/* Virtual Box */
	"vboxdisp.dll",
	"vboxhook.dll",
	"vboxmrxnp.dll",
	"vboxogl.dll",
	"vboxoglarrayspu.dll",
	"vboxoglcrutil.dll",
	"vboxoglerrorspu.dll",
	"vboxoglfeedbackspu.dll",
	"vboxoglpackspu.dll",
	"vboxoglpassthroughspu.dll",
	"vboxservice.exe",
	"vboxtray.exe",
	"vboxcontrol.exe"
};

LPCSTR VMSys32DriversFileNames[] = {
	/* VMware */
	"vmmouse.sys",
	/* Virtual Box */
	"vboxmouse.sys",
	"vboxguest.sys",
	"vboxsf.sys",
	"vboxvideo.sys"
};

// http://stackoverflow.com/questions/10385783/how-to-get-a-list-of-all-services-on-windows-7
LPCSTR VMServiceNames[] = {
	/* VMware */
	"vmtools",
	"vmhgfs",
	"vmmemctl",
	"vmmouse",
	"vmrawdisk",
	"vmusbmouse",
	"vmvss",
	"vmscsi",
	"vmxnet",
	"vmx_svga",
	"vmware tools",
	"vmware physical disk helper service"
};

/*
Enumerates all process names and checks them
against the pre-defined strings declared above.
If a process name contains one of the strings,
the process will abort.
*/
static DWORD CheckProcessName(LPSTR lpName, LPCSTR *lpArray, SIZE_T size) {
	for (SIZE_T i = 0; i < size; i++)
		if (strstr(lpName, lpArray[i]) != NULL)
			return TRUE;

	return FALSE;
}

/* Detect VMs such as VMware and VBox */
#ifdef ANTI_VIRTUAL_MACHINE
static BOOL CheckVMProcessNames(VOID) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	BOOL bResult = FALSE;
	CHAR szLowerCase[MAX_PATH];
	LPPROCESSENTRY32 lppe = malloc(sizeof(PROCESSENTRY32));
	lppe->dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, lppe) == TRUE) {
		StringToLowerCase(szLowerCase, lppe->szExeFile);
		//Debug("Original process: %s\nLowercased: %s", lppe->szExeFile, szLowerCase);
		bResult = CheckProcessName(szLowerCase, VMProcessNames, 6);
		if (bResult == TRUE) {
			free(lppe);
			CloseHandle(hSnapshot);
			return TRUE;
		}
	}

	while (Process32Next(hSnapshot, lppe) == TRUE) {
		StringToLowerCase(szLowerCase, lppe->szExeFile);
		//Debug("Original process: %s\nLowercased: %s", lppe->szExeFile, szLowerCase);
		bResult = CheckProcessName(szLowerCase, VMProcessNames, 6);
		if (bResult == TRUE)
			break;
	}

	free(lppe);
	CloseHandle(hSnapshot);

	return bResult;
}

/*
* Enumerates VMWindowNames array and tests if
* there exists a window with the same name.
* Check if working!
*/
static BOOL CheckVMWindowNames(VOID) {
	for (int i = 0; i < 5; i++) {
		if (FindWindow(VMWindowNames[i], NULL) != NULL)
			return TRUE;
	}

	return FALSE;
}

/*
Checks file artefacts in the System32 and
System32\Drivers directory
*/
static BOOL CheckVMFiles(VOID) {
	CHAR szBaseDirectory[MAX_PATH];

	GetSystemDirectory(szBaseDirectory, MAX_PATH);

	/* VMSys32FileNames */
	for (int i = 0; i < 22; i++) {
		CHAR szFileName[MAX_PATH];
		sprintf(szFileName, "%s\\%s", szBaseDirectory, VMSys32FileNames[i]);
		Debug("%s\n", szFileName);
		if (GetFileAttributes(szFileName) != INVALID_FILE_ATTRIBUTES)
			return TRUE;
	}

	/* VMSys32DriversFileNames */
	for (int i = 0; i < 5; i++) {
		CHAR szDriverFileName[MAX_PATH];
		sprintf(szDriverFileName, "%s\\%s\\%s", szBaseDirectory, "drivers", VMSys32DriversFileNames[i]);
		Debug("%s\n", szDriverFileName);
		if (GetFileAttributes(szDriverFileName) != INVALID_FILE_ATTRIBUTES)
			return TRUE;
	}

	return FALSE;
}

/*
* Enumerates all services and checks them against
* the VMServicesNames array defined above. Returns
* true if there is a match, else FALSE.
*/
static BOOL CheckVMServices(VOID) {
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (hSCManager == NULL) {
		Error("OpenSCManager");
		return FALSE;
	}

	DWORD dwNumServices = 0;
	DWORD dwServicesReturned = 0;
	DWORD dwResumeHandle = 0;
	BOOL bResult = EnumServicesStatus(hSCManager, SERVICE_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_KERNEL_DRIVER | SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &dwNumServices, &dwServicesReturned, &dwResumeHandle);
	if (bResult == FALSE && GetLastError() != ERROR_MORE_DATA) {
		Error("EnumServicesStatus first call");
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	LPENUM_SERVICE_STATUS lpess = malloc(sizeof(ENUM_SERVICE_STATUS) * dwNumServices);
	if (lpess == NULL) {
		Error("Malloc ENUM_SERVICE_STATUS");
		CloseServiceHandle(hSCManager);
		return FALSE;
	}
	bResult = EnumServicesStatus(hSCManager, SERVICE_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_KERNEL_DRIVER | SERVICE_WIN32, SERVICE_STATE_ALL, lpess, dwNumServices, &dwNumServices, &dwServicesReturned, NULL);
	if (bResult == FALSE) {
		Error("EnumServicesStatus second call");
		free(lpess);
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	for (DWORD i = 0; i < dwNumServices; i++) {
		CHAR szLowerCase[MAX_PATH];
		StringToLowerCase(szLowerCase, lpess[i].lpServiceName);
		for (int j = 0; j < 12; j++) {
			if (strstr(szLowerCase, VMServiceNames[j]) != NULL) {
				Debug("Found %s", lpess[i].lpServiceName);
				free(lpess);
				CloseServiceHandle(hSCManager);
				return TRUE;
			}
		}
	}

	free(lpess);
	CloseServiceHandle(hSCManager);
	return FALSE;
}

/*
* CPUID called with eax = 1 retrieves
* processor information. The 31st bit in
* ecx contains the value of the hypervisor
* which is always 0 on a real CPU.
*/
static BOOL CheckHypervisor(VOID) {
	BOOL bResult = FALSE;

	__asm {
		mov eax, 0x1
		cpuid
		and ecx, 0x1
		cmp ecx, 0x1
		jnz end
		mov eax, 1
		mov bResult, eax
		end :
	}

	return bResult;
}
#endif

/* Sandbox evasion */
#ifdef ANTI_SANDBOX
static VOID StallCode(VOID) {
	// rep instruction 4 cycles
}

static VOID ExtendedSleep(VOID) {
	Sleep(EXTENDED_SLEEP_TIME);
}
#endif

#ifdef ANTI_VIRTUALIZATION
BOOL CheckForVirtualization(VOID) {
	/* Anti-VM */
#ifdef ANTI_VIRTUAL_MACHINE
	//CheckVMProcessNames(); works
	//CheckVMFiles(); works
	//fix CheckVMServices();
	//CheckVMWindowNames(); works
	//CheckHypervisor(); works
#endif

	/* Anti-Sandbox */
#ifdef ANTI_SANDBOX
	ExtendedSleep();
#endif

	return FALSE;
}
#endif

#ifdef ANTI_DEBUGGING
/*
PEB->BeingDebugged method (IsDebuggerPresent)
PEB->BeingDebugged will have value of 1 if
there is a debugger on the process

Note: PEB structure may change in the future
making it unreliable
*/
static BOOL MyIsDebuggerPresent(VOID) {
	/*
	BOOL bRet = FALSE;

	PPEB peb = (PPEB)__readfsdword(0x30);
	return peb->BeingDebugged;
	__asm {
	mov eax, fs:[0x30]
	movzx eax, [eax + 0x2]
	mov bRet, eax
	}
	*/

	return *(LPBYTE)(__readfsdword(0x30) + 0x2);
}

/*
NtGlobalFlag method
If process is created by debugger, PEB +
offset 0x68 (32-bit) will have the value 0x70
*/
static BOOL CheckNtGlobalFlag(VOID) {
	DWORD dwFlag = 0;

	/*
	__asm {
	mov eax, fs:[0x30]
	mov eax, [eax + 0x68]
	mov dwFlag, eax
	}
	*/
	dwFlag = *(LPDWORD)(__readfsdword(0x30) + 0x68);

	/*
	FLG_HEAP_ENABLE_TAIL_CHECK |
	FLG_HEAP_ENABLE_FREE_CHECK |
	FLG_HEAP_VALIDATE_PARAMETERS
	*/
	return dwFlag & 0x70 ? TRUE : FALSE;
}

// not working yet
static BOOL CheckHeapFlags(VOID) {
	BOOL bRet = FALSE;
	__asm {
		mov eax, fs:[0x30]
		mov eax, [eax + 0x18]
		mov eax, [eax + 0x44]
		mov bRet, eax;			// 1 (TRUE) if there is a debugger else 0 (FALSE)
	}

	return bRet;
}

/*
NtQueryInformationProcess called with
ProcessDebugPort will set ProcessInformation
to -1 if the process is being debugged

Note: NtQueryInformationProcess may be
unreliable as it is susceptible to change
*/
static BOOL MyNtQueryInformationProcess(VOID) {
	/*
	Dynamically load the function since it's
	only available with this method (AFAIK)
	*/
	typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG, PULONG);
	pfnNtQueryInformationProcess fnNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(LoadLibrary("ntdll"), "NtQueryInformationProcess");

	if (fnNtQueryInformationProcess == NULL)
		return FALSE;

	DWORD dwDebugInfo = 0;
	NTSTATUS ntRet = fnNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwDebugInfo, sizeof(dwDebugInfo), NULL);
	if (ntRet == 0x00000000)
		if (dwDebugInfo != 0)
			return TRUE;

	return FALSE;
}

/*
NtSetInformationThread called with
ThreadInformationClass set to 0x11
(ThreadHideFromDebugger constant), the
thread will be detached from the debugger
*/
static BOOL MyNtSetInformationThread(VOID) {
	/*
	Dynamically load the function since it's
	only available with this method (AFAIK)
	*/
	typedef NTSTATUS(NTAPI *pfnNtSetInformationProcess)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG);
	pfnNtSetInformationProcess fnNtSetInformationProcess = (pfnNtSetInformationProcess)GetProcAddress(LoadLibrary("ntdll"), "NtSetInformationThread");

	if (fnNtSetInformationProcess == NULL)
		return FALSE;

	const int ThreadHideFromDebugger = 0x11;
	NTSTATUS ntRet = fnNtSetInformationProcess(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
	if (ntRet)
		return TRUE;

	return FALSE;
}

/*
Calling CloseHandle on an invalid handle
when the process is being debugged will
throw a STATUS_INVALID_HANDLE exception
*/
static BOOL MyCloseHandle(HANDLE h) {
	__try {
		CloseHandle((HANDLE)h);
	}
	__except (STATUS_INVALID_HANDLE) {
		return TRUE;
	}

	return FALSE;
}

/*
Win2K and WinXP only
*/
static BOOL MyOutputDebugString(VOID) {
	DWORD dwError = 0x1337;
	SetLastError(dwError);
	OutputDebugString("Hello world");

	if (GetLastError() == dwError)
		return TRUE;

	return FALSE;
}

/*
If the process is being debugged and the int
2Dh instruction is executed with the trace
flag, no exception will be generated the following
byte will be skipped and execution will continue
*/
static BOOL CheckInt2D(VOID) {
	__try {
		__asm {
			int 0x2D
			mov eax, 1    // anti-trace
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;     // process not being debugged
	}

	return TRUE;
}

/*
Uses precision timer to calculate the delta
time between intructions. By raising an exception,
it forces extra time onto the debugging process
hence creating a larger delta
*/
static BOOL RdtscTimer(DWORD dwTimeThreshold) {
	DWORD64 dwInitialTime = 0;

	__try {
		dwInitialTime = __rdtsc();
		__asm {
			xor eax, eax
			div eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// do nothing
	}

	if (__rdtsc() - dwInitialTime > dwTimeThreshold)
		return FALSE;
	else
		return TRUE;
}

#ifdef FIND_WINDOW_NAMES
/*
Enumerates all windows and checks all window names
for any of the pre-defined strings declared above.
Returns TRUE if one exists, else FALSE
*/
static BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	CHAR szWindowText[MAX_PATH];
	CHAR szLowerCase[MAX_PATH];

	if (GetWindowText(hWnd, szWindowText, MAX_PATH) != 0) {
		//Debug("Found window: %s\n", szWindowText);
		StringToLowerCase(szLowerCase, szWindowText);
		for (int i = 0; i < 5; i++)
			if (strstr(szLowerCase, DebuggerNames[i]) != NULL) {
				*(PBOOL)lParam = TRUE;
				return FALSE;
			}

		for (int i = 0; i < 4; i++)
			if (strstr(szLowerCase, MonitoringToolNames[i]) != NULL) {
				*(PBOOL)lParam = TRUE;
				return FALSE;
			}
	}

	return TRUE;
}

/*
Starts a window enumeration
*/
static BOOL CheckWindowNames(VOID) {
	BOOL bResult = FALSE;
	EnumWindows(EnumWindowsProc, (LPARAM)&bResult);

	return bResult;
}
#endif

// multithread this on an infinite loop?
// only 32-bit processes
static BOOL CheckProcessNames(VOID) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	BOOL bResult = FALSE;
	CHAR szLowerCase[MAX_PATH];
	LPPROCESSENTRY32 lppe = malloc(sizeof(PROCESSENTRY32));
	lppe->dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, lppe) == TRUE) {
		StringToLowerCase(szLowerCase, lppe->szExeFile);
		//Debug("Original process: %s\nLowercased: %s", lppe->szExeFile, szLowerCase);
		bResult = CheckProcessName(szLowerCase, DebuggerNames, 5) |
			CheckProcessName(szLowerCase, MonitoringToolNames, 4);
		if (bResult == TRUE) {
			free(lppe);
			CloseHandle(hSnapshot);
			return TRUE;
		}
	}

	while (Process32Next(hSnapshot, lppe) == TRUE) {
		StringToLowerCase(szLowerCase, lppe->szExeFile);
		//Debug("Original process: %s\nLowercased: %s", lppe->szExeFile, szLowerCase);
		bResult = CheckProcessName(szLowerCase, DebuggerNames, 5) |
			CheckProcessName(szLowerCase, MonitoringToolNames, 4);
		if (bResult == TRUE)
			break;
	}

	free(lppe);
	CloseHandle(hSnapshot);

	return bResult;
}

// check for debuggers
BOOL CheckForDebuggers(VOID) {
	BOOL bResult = FALSE;

#ifdef FIND_WINDOW_NAMES
	// windows with names of debuggers
	bResult |= CheckWindowNames();
#endif

	// processes with names of debuggers 
	// and monitoring tools
	bResult |= CheckProcessNames();

	// direct checks for debugging activity
	bResult |=
		// IsDebuggerPresent
		MyIsDebuggerPresent() |
		// NtGlobalFlag
		CheckNtGlobalFlag() |
		// NtQueryInformationProcess
		MyNtQueryInformationProcess() |
		// NtQueryInformationProcess
		MyNtQueryInformationProcess() |
		// CloseHandle(INVALID_HANDLE)
		MyCloseHandle((HANDLE)0xDEADBEEF) |
		// int 2Dh
		CheckInt2D();

	// prevent debuggers from receiving events
	// DetachFromDebugger
	//MyNtSetInformationThread();

	// heap flags

	// OutputDebugString
	if ((IsWindowsXPOrGreater() ||
		IsWindowsXPSP1OrGreater() ||
		IsWindowsXPSP2OrGreater() ||
		IsWindowsXPSP3OrGreater()) &&
		!IsWindowsVistaOrGreater()) {
		bResult |= MyOutputDebugString();
	}

	// timing
	//RdtscTimer(0x10000);

	return bResult;
}
#endif