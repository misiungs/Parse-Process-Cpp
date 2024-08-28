#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>


void EnableDebugPriv()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

    CloseHandle(hToken);
}

HANDLE FindProcess(wchar_t procName[])
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (_wcsicmp(entry.szExeFile, procName) == 0)
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                CloseHandle(snapshot);
                return hProcess;
            }
        }
    }

    CloseHandle(snapshot);
    return 0;
}

bool ReadMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
    SIZE_T bytesRead;
    if (ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &bytesRead)) {
        if (bytesRead == nSize) {
            return true;
        }
        else {
            std::cerr << "Partial read: " << bytesRead << " of " << nSize << " bytes." << std::endl;
        }
    }
    else {
        std::cerr << "Failed to read memory. Error: " << GetLastError() << std::endl;
    }
    return false;
}

int main() {
    wchar_t procName[] = L"MessageLoop.exe";
    HANDLE procHandle = FindProcess(procName);
    DWORD pid = GetProcessId(procHandle);
    //DWORD pid = 14320; // Replace with the PID of the process you want to open
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess == NULL) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Get the base address of the main module
    HMODULE hModule;
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, &hModule, sizeof(hModule), &cbNeeded)) {
        std::cerr << "Failed to enumerate process modules. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Read the DOS header
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadMemory(hProcess, hModule, &dosHeader, sizeof(dosHeader))) {
        CloseHandle(hProcess);
        return 1;
    }

    // Read the NT headers
    IMAGE_NT_HEADERS ntHeaders;
    LPCVOID ntHeadersAddress = (LPCVOID)((BYTE*)hModule + dosHeader.e_lfanew);
    if (!ReadMemory(hProcess, ntHeadersAddress, &ntHeaders, sizeof(ntHeaders))) {
        CloseHandle(hProcess);
        return 1;
    }

    // Get the Import Directory RVA
    DWORD importDirectoryRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importDirectoryRVA == 0) {
        CloseHandle(hProcess);
        return 1; // No import directory
    }

    // Calculate the address of the Import Directory
    LPCVOID importDescriptorAddress = (LPCVOID)((BYTE*)hModule + importDirectoryRVA);

    // Read the Import Descriptor
    IMAGE_IMPORT_DESCRIPTOR importDescriptor;
    if (!ReadMemory(hProcess, importDescriptorAddress, &importDescriptor, sizeof(importDescriptor))) {
        CloseHandle(hProcess);
        return 1;
    }

    // Output some header information
    std::cout << "DOS Header:" << std::endl;
    std::cout << "  e_magic: " << std::hex << dosHeader.e_magic << std::endl;
    std::cout << "  e_lfanew: " << std::hex << dosHeader.e_lfanew << std::endl;

    std::cout << "NT Headers:" << std::endl;
    std::cout << "  Signature: " << std::hex << ntHeaders.Signature << std::endl;
    std::cout << "  FileHeader.Machine: " << std::hex << ntHeaders.FileHeader.Machine << std::endl;
    std::cout << "  OptionalHeader.Magic: " << std::hex << ntHeaders.OptionalHeader.Magic << std::endl;
    std::cout << "  OptionalHeader.SizeOfCode: " << std::hex << ntHeaders.OptionalHeader.SizeOfCode << std::endl;
    std::cout << "  OptionalHeader.AddressOfEntryPoint: " << std::hex << ntHeaders.OptionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "  OptionalHeader.SectionAlignment: " << std::hex << ntHeaders.OptionalHeader.SectionAlignment << std::endl;
    std::cout << "  OptionalHeader.FileAlignment: " << std::hex << ntHeaders.OptionalHeader.FileAlignment << std::endl;

    // Iterate over the Import Descriptors
    while (true) {
        IMAGE_IMPORT_DESCRIPTOR importDescriptor;
        if (!ReadMemory(hProcess, importDescriptorAddress, &importDescriptor, sizeof(importDescriptor))) {
            CloseHandle(hProcess);
            return 1;
        }

        if (importDescriptor.Name == 0) {
            break; // No more descriptors
        }

        // Read the DLL name
        char dllName[256];
        LPCVOID dllNameAddress = (LPCVOID)((BYTE*)hModule + importDescriptor.Name);
        if (!ReadMemory(hProcess, dllNameAddress, dllName, sizeof(dllName))) {
            CloseHandle(hProcess);
            return 1;
        }
        std::cout << "DLL: " << dllName << std::endl;

        // Iterate over the Thunks
        LPCVOID thunkAddress = (LPCVOID)((BYTE*)hModule + importDescriptor.OriginalFirstThunk);
        while (true) {
            IMAGE_THUNK_DATA thunkData;
            if (!ReadMemory(hProcess, thunkAddress, &thunkData, sizeof(thunkData))) {
                CloseHandle(hProcess);
                return 1;
            }

            if (thunkData.u1.AddressOfData == 0) {
                break; // No more thunks
            }

            // Read the function name
            LPCVOID functionNameAddress = (LPCVOID)((BYTE*)hModule + thunkData.u1.AddressOfData + 2); // Skip the hint
            char functionName[256];
            if (!ReadMemory(hProcess, functionNameAddress, functionName, sizeof(functionName))) {
                CloseHandle(hProcess);
                return 1;
            }
            std::cout << "  Function: " << functionName << std::endl;

            thunkAddress = (LPCVOID)((BYTE*)thunkAddress + sizeof(IMAGE_THUNK_DATA));
        }

        importDescriptorAddress = (LPCVOID)((BYTE*)importDescriptorAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    CloseHandle(hProcess);
    return 0;
}
