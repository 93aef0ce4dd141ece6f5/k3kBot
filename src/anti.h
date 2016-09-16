#pragma once
#ifndef ANTI_H
#define ANTI_H

//#define ANTI_VIRTUALIZATION
#define ANTI_VIRTUAL_MACHINE
#define ANTI_SANDBOX
//#define ANTI_DEBUGGING

#define FIND_WINDOW_NAMES

#ifdef ANTI_SANDBOX
#define EXTENDED_SLEEP_TIME 1000 * 60 * 10 /* 10 minutes */
#endif

BOOL CheckForVirtualization(VOID);
BOOL CheckForDebuggers(VOID);

#endif // !ANTI_H