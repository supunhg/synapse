#include "MinHook.h"
#include <windows.h>
#include <psapi.h>
#include <stdio.h>

typedef struct HookEntry {
    LPVOID target;
    LPVOID detour;
    LPVOID original;
    int enabled;
} HookEntry;

static CRITICAL_SECTION mh_cs;
static HookEntry hooks[64];
static int hooks_count = 0;

static void init_cs_once(void) {
    static int init = 0;
    if (!init) { InitializeCriticalSection(&mh_cs); init = 1; }
}

// Patch IAT entries in a module replacing any pointer equal to 'target' with 'detour'.
static void PatchIATForModule(HMODULE hMod, LPVOID target, LPVOID detour, LPVOID *origFound) {
    if (!hMod) return;
    unsigned char *base = (unsigned char *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    IMAGE_DATA_DIRECTORY impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0) return;
    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + impDir.VirtualAddress);
    for (; imp->Name; imp++) {
        IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
        for (; thunk->u1.Function; thunk++) {
            LPVOID *pfn = (LPVOID *)&thunk->u1.Function;
            if (*pfn == target) {
                DWORD old;
                if (VirtualProtect(pfn, sizeof(LPVOID), PAGE_READWRITE, &old)) {
                    if (origFound && !*origFound) *origFound = *pfn;
                    *pfn = detour;
                    VirtualProtect(pfn, sizeof(LPVOID), old, &old);
                }
            }
        }
    }
}

static void EnableIATHooksForTarget(LPVOID target, LPVOID detour, LPVOID *origFound) {
    HMODULE mods[1024]; DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return;
    int count = needed / sizeof(HMODULE);
    for (int i = 0; i < count; i++) PatchIATForModule(mods[i], target, detour, origFound);
}

MH_STATUS MH_Initialize(void) {
    init_cs_once();
    return MH_OK;
}

MH_STATUS MH_Uninitialize(void) {
    // nothing
    return MH_OK;
}

MH_STATUS MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal) {
    EnterCriticalSection(&mh_cs);
    if (hooks_count >= (int)(sizeof(hooks)/sizeof(hooks[0]))) { LeaveCriticalSection(&mh_cs); return -1; }
    hooks[hooks_count].target = pTarget;
    hooks[hooks_count].detour = pDetour;
    hooks[hooks_count].original = pTarget; // original callable pointer
    hooks[hooks_count].enabled = 0;
    if (ppOriginal) *ppOriginal = hooks[hooks_count].original;
    hooks_count++;
    LeaveCriticalSection(&mh_cs);
    return MH_OK;
}

MH_STATUS MH_RemoveHook(LPVOID pTarget) {
    EnterCriticalSection(&mh_cs);
    for (int i = 0; i < hooks_count; i++) {
        if (hooks[i].target == pTarget) {
            // disable if enabled
            if (hooks[i].enabled) MH_DisableHook(pTarget);
            // compact array
            for (int j = i; j+1 < hooks_count; j++) hooks[j] = hooks[j+1];
            hooks_count--;
            break;
        }
    }
    LeaveCriticalSection(&mh_cs);
    return MH_OK;
}

MH_STATUS MH_EnableHook(LPVOID pTarget) {
    EnterCriticalSection(&mh_cs);
    for (int i = 0; i < hooks_count; i++) {
        if (hooks[i].target == pTarget) {
            LPVOID orig = NULL;
            EnableIATHooksForTarget(hooks[i].target, hooks[i].detour, &orig);
            hooks[i].enabled = 1;
            if (orig) hooks[i].original = orig;
            break;
        }
    }
    LeaveCriticalSection(&mh_cs);
    return MH_OK;
}

MH_STATUS MH_DisableHook(LPVOID pTarget) {
    EnterCriticalSection(&mh_cs);
    // naive: not restoring original pointers
    for (int i = 0; i < hooks_count; i++) if (hooks[i].target == pTarget) hooks[i].enabled = 0;
    LeaveCriticalSection(&mh_cs);
    return MH_OK;
}
