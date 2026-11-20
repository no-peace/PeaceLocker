#include <windows.h>
#include <string>
#include "common.h"

struct QueuedBlock {
    DWORD        pid;
    UniqueHandle hProc;
    std::wstring label;
    std::wstring type;
    bool         suspended;
};

void StartMonitor(HWND hwndMain);
void StopMonitor();

// Called by GUI after PIN result
void MonitorAllow(QueuedBlock& item);
void MonitorKillPid(DWORD pid);

// Queue management
bool PopBlock(QueuedBlock& out);
bool HasQueuedBlocks();
