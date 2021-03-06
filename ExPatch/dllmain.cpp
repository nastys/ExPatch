// dllmain.cpp : Defines the entry point for the DLL application.
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
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

HMODULE hm = 0;

toml::table cfg_file;
bool cfg_overwrite = false;

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

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hm = hModule;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

void message(const char* message, UINT type)
{
	HANDLE hActCtx;
	ACTCTX actCtx = {};
	actCtx.cbSize = sizeof(actCtx);
	actCtx.dwFlags = ACTCTX_FLAG_HMODULE_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID;
	actCtx.hModule = hm;
	actCtx.lpResourceName = MAKEINTRESOURCE(2);

	hActCtx = CreateActCtx(&actCtx);
	if (hActCtx != INVALID_HANDLE_VALUE) {
		ULONG_PTR cookie;
		ActivateActCtx(hActCtx, &cookie);

		MessageBoxA(0, message, "ExPatch", type);

		DeactivateActCtx(0, cookie);
		ReleaseActCtx(hActCtx);
	}
}

extern "C"
{
	void __declspec(dllexport) Init()
	{
		printf("[ExPatch] Initializing...\n");
		try
		{
			cfg_file = toml::parse_file("config.toml");
			try
			{
				cfg_overwrite = cfg_file["permanent"].value_or(false);
			}
			catch (std::exception& exception)
			{
				char strbuf[500] = {};
				sprintf(strbuf, "Failed to read config values.\n%s.", exception.what());
				message(strbuf, MB_ICONWARNING);

			}
		}
		catch (std::exception& exception)
		{
			char strbuf[500] = {};
			sprintf(strbuf, "Failed to parse config.toml:\n%s.", exception.what());
			message(strbuf, MB_ICONWARNING);
		}

		void* addr = fullScan(bytes_orig.data(), bytes_orig.size());

		if (addr == nullptr)
		{
			message("Unsupported game version.", MB_ICONERROR);
			return;
		}

		printf("[ExPatch] Address: %llx\n", addr);

		if (cfg_overwrite)
		{
			printf("[ExPatch] Unlocking and overwriting save...\n");
			const std::vector<uint8_t> ass = { 0x48, 0xB8,
				byteAt((uint64_t)hook_overwsave, 0),
				byteAt((uint64_t)hook_overwsave, 1),
				byteAt((uint64_t)hook_overwsave, 2),
				byteAt((uint64_t)hook_overwsave, 3),
				byteAt((uint64_t)hook_overwsave, 4),
				byteAt((uint64_t)hook_overwsave, 5),
				byteAt((uint64_t)hook_overwsave, 6),
				byteAt((uint64_t)hook_overwsave, 7),
				0xFF, 0xE0 };
			InjectCode(addr, ass);
		}
		else
		{
			printf("[ExPatch] Unlocking without overwriting save...\n");
			InjectCode(addr, bytes_new);
		}
		printf("[ExPatch] Done.\n");
	}
}