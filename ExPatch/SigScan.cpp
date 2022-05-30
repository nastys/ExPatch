//MIT License
//
//Copyright(c) 2022 Skyth
//
//Permission is hereby granted, free of charge, to any person obtaining a copy of this softwareand associated documentation files(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and /or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions :
//
//The above copyright noticeand this permission notice shall be included in all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "SigScan.h"
#include <Psapi.h>

MODULEINFO moduleInfo;

const MODULEINFO& getModuleInfo()
{
    if (moduleInfo.SizeOfImage)
        return moduleInfo;

    ZeroMemory(&moduleInfo, sizeof(MODULEINFO));
    GetModuleInformation(GetCurrentProcess(), GetModuleHandle(nullptr), &moduleInfo, sizeof(MODULEINFO));

    return moduleInfo;
}

void* sigScan(const char* signature, const char* mask)
{
    const MODULEINFO& info = getModuleInfo();
    const size_t length = strlen(mask);

    for (size_t i = 0; i < info.SizeOfImage - length; i++)
    {
        char* memory = (char*)info.lpBaseOfDll + i;

        size_t j;
        for (j = 0; j < length; j++)
        {
            if (mask[j] != '?' && signature[j] != memory[j])
                break;
        }

        if (j == length) 
            return memory;
    }

    return nullptr;
}

void* fullScan(const uint8_t* data, size_t length)
{
    const MODULEINFO& info = getModuleInfo();

    for (size_t i = 0; i < info.SizeOfImage - length; i++)
    {
        uint8_t* memory = (uint8_t*)info.lpBaseOfDll + i;

        size_t j;
        for (j = 0; j < length; j++)
        {
            if (data[j] != memory[j])
                break;
        }

        if (j == length)
            return memory;
    }

    return nullptr;
}
