// Minimal MinHook-compatible shim header for this project
#pragma once
#include <windows.h>

typedef int MH_STATUS;
#define MH_OK 0

MH_STATUS MH_Initialize(void);
MH_STATUS MH_Uninitialize(void);
MH_STATUS MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal);
MH_STATUS MH_RemoveHook(LPVOID pTarget);
MH_STATUS MH_EnableHook(LPVOID pTarget);
MH_STATUS MH_DisableHook(LPVOID pTarget);