// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <vector>

const uint64_t addr = 0x1401D9A50;
const std::vector<uint8_t> bytes_orig = { 0x0F, 0xB6, 0x81, 0x1D, 0x01, 0x00 };
const std::vector<uint8_t> bytes_new = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

void InjectCode(void* address, const std::vector<uint8_t> data)
{
    const size_t byteCount = data.size() * sizeof(uint8_t);

    DWORD oldProtect;
    VirtualProtect(address, byteCount, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(address, data.data(), byteCount);
    VirtualProtect(address, byteCount, oldProtect, nullptr);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        puts("[ExPatch] Initializing...");
        if (memcmp(bytes_orig.data(), (void*)addr, 6))
        {
            puts("[ExPatch] E: Wrong game version.");
            return FALSE;
        }

        InjectCode((void*)addr, bytes_new);
        puts("[ExPatch] Done.");
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

