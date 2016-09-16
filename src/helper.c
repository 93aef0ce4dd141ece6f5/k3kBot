#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>

#include "main.h"
#include "helper.h"

VOID Debug(LPCSTR fmt, ...) {
#ifdef DEBUG
	CHAR szMsg[BUFSIZ];
	va_list args;

	va_start(args, fmt);
	vsprintf(szMsg, fmt, args);

	MessageBox(NULL, szMsg, NAME, MB_OK);

	va_end(args);
#endif
}

VOID Error(LPCSTR szErrMsg) {
#ifdef DEBUG
	CHAR szMsg[BUFSIZ];

	sprintf(szMsg, "%s error: %lu", szErrMsg, GetLastError());

	MessageBox(NULL, szMsg, NAME, MB_OK);
#endif
}

VOID StringToLowerCase(LPSTR lpDest, LPCSTR lpSrc) {
	strcpy(lpDest, lpSrc);

	for (int i = 0; i < (int)strlen(lpSrc); i++)
		if (lpSrc[i] >= 'A' && lpSrc[i] <= 'Z')
			lpDest[i] = lpSrc[i] + 32;
}