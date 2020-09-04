#include "KeBridge.h"

HANDLE KbOpenHandle(LPCWSTR DeviceName)
{
    return CreateFileW(DeviceName, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);
}

BOOL ReadKernelMemory(HANDLE hDriver, OUT PVOID Dest, IN PVOID Src, IN ULONG Size)
{
    if (!Dest || !Src || !Size)
        return FALSE;

    KB_COPY_MOVE_MEMORY_IN Data = { 0 };
    Data.Src = Src;
    Data.Dest = Dest;
    Data.Size = Size;
    Data.Intersects = FALSE;

    if (hDriver == INVALID_HANDLE_VALUE)
        return FALSE;

    DWORD dwIoCtl = CTL_CODE(0x8000, CTL_BASE + 27, 0, FILE_ANY_ACCESS);
    if (!DeviceIoControl(hDriver, dwIoCtl, &Data, sizeof(Data), nullptr, NULL, NULL, NULL))
        return FALSE;

    return TRUE;
}
