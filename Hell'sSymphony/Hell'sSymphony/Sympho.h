#pragma once
#include <stdint.h>
#include "HellsHall.h"

LPVOID GiveMeMyFunc(char* name, HMODULE module);
HMODULE GiveMeMyModule(uint64_t expectedHash);
void WideCharToUpperChar(PWCHAR wString, PCHAR buffer, SIZE_T size);
uint64_t Hashed(PCHAR String);
VOID getSysFuncStruct(OUT PSysFunc psF);
uint32_t crc32b(const uint8_t* str);
HANDLE GiveMeThisProcess(HMODULE fnc);
BOOL InitilizeSysFunc(CHAR* uSysFuncHash);
