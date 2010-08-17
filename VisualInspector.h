#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KDEXT_64BIT
#include <wdbgexts.h>
#include <dbgeng.h>

#pragma warning(disable:4201)
#include <extsfns.h>

#ifdef __cplusplus
extern "C" {
#endif


#define INIT_API()                             \
    HRESULT Status;                            \
    if ((Status = ExtQuery(Client)) != S_OK) return Status;

#define EXT_RELEASE(Unk) \
    ((Unk) != NULL ? ((Unk)->Release(), (Unk) = NULL) : NULL)

#define EXIT_API     ExtRelease

extern PDEBUG_CLIENT4        g_ExtClient;
extern PDEBUG_CONTROL        g_ExtControl;
extern PDEBUG_SYMBOLS3       g_ExtSymbols;
extern PDEBUG_REGISTERS		 g_ExtRegisters;

extern BOOL  Connected;
extern ULONG TargetMachine;

HRESULT ExtQuery(PDEBUG_CLIENT4 Client);

void ExtRelease(void);

HRESULT NotifyOnTargetAccessible(PDEBUG_CONTROL Control);

#ifdef __cplusplus
}
#endif
