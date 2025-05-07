#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <stdint.h>
#include <ctype.h>
#include "Sympho.h"
#include "HellsHall.h"
#define SEED 4
#define RANGE       0x1E
void ToUpperCase(char* str);

typedef struct _NTDLL {

    PBYTE                       pNtdll;
    PIMAGE_DOS_HEADER           pImgDos;
    PIMAGE_NT_HEADERS           pImgNtHdrs;
    PIMAGE_EXPORT_DIRECTORY     pImgExpDir;
    PDWORD                      pdwArrayOfFunctions;
    PDWORD                      pdwArrayOfNames;
    PWORD                       pwArrayOfOrdinals;

}NTDLL, * PNTDLL;


NTDLL       NtdllSt = { 0 };
SysFunc     sF = { 0 };



BOOL InitilizeNtdllConfig() {

    //  CHECK
    if (NtdllSt.pdwArrayOfFunctions != NULL && NtdllSt.pdwArrayOfNames != NULL && NtdllSt.pwArrayOfOrdinals != NULL)
        return TRUE;


    PPEB                    pPeb = NULL;
    PLDR_DATA_TABLE_ENTRY   pDte = NULL;
    PBYTE                   uNtdll = NULL;

    RtlSecureZeroMemory(&NtdllSt, sizeof(NTDLL));

    //  PEB
    pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb == NULL) {
        return FALSE;
    }

    //  NTDLL
    pDte = GiveMeMyModule(0x9B90848C8B008677);
    if (!pDte) {
        return FALSE;
    }


    NtdllSt.pNtdll = uNtdll = pDte;

    //  DOS
    NtdllSt.pImgDos = (PIMAGE_DOS_HEADER)uNtdll;
    if (NtdllSt.pImgDos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("ntdll pb\n");
        return FALSE;
    }


    //  NT
    NtdllSt.pImgNtHdrs = (PIMAGE_NT_HEADERS)(uNtdll + NtdllSt.pImgDos->e_lfanew);
    if (NtdllSt.pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        printf("fuck\n");
        return FALSE;
    }


    //  EXPORT
    NtdllSt.pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uNtdll + NtdllSt.pImgNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);
    if (!NtdllSt.pImgExpDir || !NtdllSt.pImgExpDir->Base)
        return NULL;


    //  ARRAYS
    NtdllSt.pdwArrayOfFunctions = (PDWORD)(uNtdll + NtdllSt.pImgExpDir->AddressOfFunctions);
    NtdllSt.pdwArrayOfNames = (PDWORD)(uNtdll + NtdllSt.pImgExpDir->AddressOfNames);
    NtdllSt.pwArrayOfOrdinals = (PWORD)(uNtdll + NtdllSt.pImgExpDir->AddressOfNameOrdinals);

    //  CHECK
    if (!NtdllSt.pdwArrayOfFunctions || !NtdllSt.pdwArrayOfNames || !NtdllSt.pwArrayOfOrdinals)
        return FALSE;
    return TRUE;
}


BOOL InitilizeSysFunc(CHAR* uSysFuncHash) {

    if (!uSysFuncHash) {
        printf("Pas de parametre\n");
        return FALSE;
    }

    if (!NtdllSt.pNtdll && !InitilizeNtdllConfig()) {
        printf("Probleme d'initialization de NTDLL\n");
        return FALSE;
    }

    for (DWORD i = 0; i < NtdllSt.pImgExpDir->NumberOfFunctions; i++) {
        CHAR* cFuncName = (CHAR*)(NtdllSt.pdwArrayOfNames[i] + NtdllSt.pNtdll);
        if (strcmp(cFuncName, uSysFuncHash) == 0) {
            sF.uHash = uSysFuncHash;
            sF.pAddress = (PVOID)(NtdllSt.pdwArrayOfFunctions[NtdllSt.pwArrayOfOrdinals[i]] + NtdllSt.pNtdll);

            DWORD j = 0;
            while (TRUE) {
                if (*((PBYTE)sF.pAddress + j) == 0xC3 && !sF.pInst)
                    return FALSE;

                // Recherche des instructions spécifiques
                if (*((PBYTE)sF.pAddress + j + 0x00) == 0x4C &&
                    *((PBYTE)sF.pAddress + j + 0x01) == 0x8B &&
                    *((PBYTE)sF.pAddress + j + 0x02) == 0xD1 &&
                    *((PBYTE)sF.pAddress + j + 0x03) == 0xB8) {

                    BYTE low = *((PBYTE)sF.pAddress + j + 0x04);
                    BYTE high = *((PBYTE)sF.pAddress + j + 0x05);

                    // Récupérer le SSN
                    sF.wSSN = (high << 0x08) | low;

                    // Recherche de l'adresse de l'instruction syscall
                    for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
                        if (*((PBYTE)sF.pAddress + j + z) == 0x0F && *((PBYTE)sF.pAddress + j + x) == 0x05) {
                            sF.pInst = (sF.pAddress + j + z);
                            break;
                        }

                    }

                    if (sF.wSSN && sF.pInst)
                        return TRUE;
                    else
                        return FALSE;
                }

                j++;
            }
        }
    }
    printf("Didnt find nothing\n");

    return FALSE;
}




/**
* Mise en place de mes fonctions perso
*
**/

void ToUpperCase(char* str) {
    while (*str) {
        *str = toupper((unsigned char)*str);
        str++;
    }
}


VOID getSysFuncStruct(OUT PSysFunc psF) {

    psF->pAddress = sF.pAddress;
    psF->pInst = sF.pInst;
    psF->uHash = sF.uHash;
    psF->wSSN = sF.wSSN;
}

uint64_t Hashed(const char* String) {
    uint32_t hash1 = SEED;
    uint32_t hash2 = 0xDEADBEEF;

    while (*String) {
        hash1 += (hash1 << 8) ^ (uint32_t)(*String);
        hash2 += (hash2 << 8) ^ (uint32_t)(*String);
        String++;
    }

    uint64_t combinedHash = ((uint64_t)hash1 << 32) | hash2;

    return combinedHash;
}


// Convertit une chaîne WCHAR en CHAR et la met en majuscules
void WideCharToUpperChar(PWCHAR wString, PCHAR buffer, SIZE_T size) {
    if (!wString || !buffer) return;
    int len = WideCharToMultiByte(CP_ACP, 0, wString, -1, buffer, (int)size, NULL, NULL);
    if (len > 0) {
        for (int i = 0; i < len; i++) {
            buffer[i] = (char)toupper(buffer[i]); // Convertir en majuscules
        }
    }
}

HMODULE GiveMeMyModule(uint64_t expectedHash) {

#ifdef _WIN64
    PPEB      pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
    PPEB      pPeb = (PEB*)(__readfsdword(0x30));
#endif

    if (!expectedHash) return NULL;

    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    while (pDte) {

        if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {

            CHAR UpperCaseDllName[MAX_PATH];
            int i = 0;
            while (pDte->FullDllName.Buffer[i]) {
                UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
                i++;
            }
            UpperCaseDllName[i] = '\0';

            uint64_t hash = Hashed(UpperCaseDllName);
            if (hash == expectedHash) {
                return pDte->Reserved2[0];
            }
        }
        else {
            printf("Error during listing LDR\n");
            break;
        }

        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }

    return NULL;
}

LPVOID GiveMeMyFunc(char* name, HMODULE module) {
    if (!module) return NULL;

    PBYTE pBase = (PBYTE)module;
    PIMAGE_DOS_HEADER pDOS_HEADER = (PIMAGE_DOS_HEADER)pBase;

    if (pDOS_HEADER->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error retrieving DOS HEADER\n");
        return NULL;
    }

    PIMAGE_NT_HEADERS pNT_HEADER = (PIMAGE_NT_HEADERS)(pBase + pDOS_HEADER->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pDOS_OPT_HEADER = &pNT_HEADER->OptionalHeader;

    if (pDOS_OPT_HEADER->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        printf("No export table found.\n");
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY pDOS_EXPORTDIR = (PIMAGE_EXPORT_DIRECTORY)(pBase + pDOS_OPT_HEADER->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pAddressOfNames = (PDWORD)(pBase + pDOS_EXPORTDIR->AddressOfNames);
    PDWORD pAddressOfFunction = (PDWORD)(pBase + pDOS_EXPORTDIR->AddressOfFunctions);

    PWORD pAddressOfNameOrdinals = (PWORD)(pBase + pDOS_EXPORTDIR->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pDOS_EXPORTDIR->NumberOfNames; i++) {
        char* FuncName = (char*)(pBase + pAddressOfNames[i]);

        if (strcmp(FuncName, name) == 0) {
            printf("Found function: %s\n", FuncName);
            return (PVOID)(pBase + pAddressOfFunction[pAddressOfNameOrdinals[i]]);
        }
    }

    printf("Function not found\n");
    return NULL;
}















