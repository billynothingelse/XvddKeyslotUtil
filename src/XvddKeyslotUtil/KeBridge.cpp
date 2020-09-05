#include "KeBridge.h"

BOOL KbInstallDriver(LPCWSTR FilePath, LPCWSTR DriverName, DWORD DriverType)
{
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

    if (hSCManager == NULL) return FALSE;

    SC_HANDLE hService = CreateService(
        hSCManager, DriverName, DriverName,
        SERVICE_ALL_ACCESS, DriverType, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, FilePath,
        NULL, NULL, NULL, NULL, NULL
    );

    if (hService == NULL) {
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    LPCWSTR Arguments = NULL;
    BOOL Status = StartService(hService, 0, &Arguments);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return Status;
}

BOOL KbDeleteDriver(LPCWSTR DriverName)
{
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL) return FALSE;

    SC_HANDLE hService = OpenService(hSCManager, DriverName, SERVICE_ALL_ACCESS);
    if (hService == NULL) {
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    SERVICE_STATUS ServiceStatus;
    ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus);
    BOOL Status = DeleteService(hService);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return Status;
}

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
