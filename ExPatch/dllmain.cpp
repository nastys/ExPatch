// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <vector>
#include "toml.hpp"
#include "SigScan.h"

void* addr = nullptr;
//const char signature[] = "\xE8\x00\x00\x00\x00\x41\x8D\x4D\x01";
//const char mask[] = "x????xxxx";
const std::vector<uint8_t> bytes_orig = { 0x0F, 0xB6, 0x81, 0x1D, 0x01, 0x00, 0x00, 0xC3 };
const std::vector<uint8_t> bytes_new = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

toml::table cfg_file;
bool cfg_overwrite = false;

bool console = false;

void InjectCode(void* address, const std::vector<uint8_t> data)
{
    const size_t byteCount = data.size() * sizeof(uint8_t);

    DWORD oldProtect;
    VirtualProtect(address, byteCount, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(address, data.data(), byteCount);
    VirtualProtect(address, byteCount, oldProtect, nullptr);
}

uint8_t byteAt(uint64_t num, unsigned char pos)
{
    return (num >> (8 * pos)) & 0xff;
}

__int64 __fastcall hook_overwsave(__int64 a1)
{
    return *(unsigned __int8*)(a1 + 0x11D) = 1;
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
        console = freopen("CONOUT$", "w", stdout) != NULL;

        if(console) printf("[ExPatch] Initializing...\n");

        try
        {
            cfg_file = toml::parse_file("config.toml");
            try
            {
                cfg_overwrite = cfg_file["permanent"].value_or(false);
            }
            catch (std::exception& exception)
            {
                if (console) printf("Failed to read config values. %s\n", exception.what());
            }
        }
        catch (std::exception& exception)
        {
            if (console) printf("Failed to parse config.toml: %s\n", exception.what());
        }

        void* addr = fullScan(bytes_orig.data(), bytes_orig.size());

        if (addr == nullptr)
        {
            if (console) printf("[ExPatch] E: Wrong game version.\n");
            return FALSE;
        }

        if (console) printf("[ExPatch] Address: %llx\n", addr);

        if (cfg_overwrite)
        {
            if (console) printf("[ExPatch] Unlocking and overwriting save...\n");
            const std::vector<uint8_t> ass = { 0x48, 0xB8,
                byteAt((uint64_t)hook_overwsave, 0),
                byteAt((uint64_t)hook_overwsave, 1),
                byteAt((uint64_t)hook_overwsave, 2),
                byteAt((uint64_t)hook_overwsave, 3),
                byteAt((uint64_t)hook_overwsave, 4),
                byteAt((uint64_t)hook_overwsave, 5),
                byteAt((uint64_t)hook_overwsave, 6),
                byteAt((uint64_t)hook_overwsave, 7),
                0xFF, 0xE0};
            InjectCode(addr, ass);
        }
        else
        {
            if (console) printf("[ExPatch] Unlocking without overwriting save...\n");
            InjectCode(addr, bytes_new);
        }
        if (console) printf("[ExPatch] Done.\n");
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

