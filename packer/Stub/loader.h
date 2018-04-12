#pragma once
#include <stdint.h>
#include <Windows.h>


// This loader will take a binary as a input bytes and make it run in memory
// This is done by reading the sections and bytes, allocating memory, doing fixups as necessary
int loader(uint8_t * data);
