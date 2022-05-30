#pragma once
#include <cstdint>

void* sigScan(const char* signature, const char* mask);
void* fullScan(const uint8_t* data, size_t length);
