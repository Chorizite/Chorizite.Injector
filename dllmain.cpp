// dllmain.cpp : Defines the entry point for the DLL application.

#include "pch.h"
#include <iostream>
#include <fstream>
#include "Shlobj_core.h"
#include "CoreCLR.hpp"

#include <locale>
#include <codecvt>
#include <string>
#include <shellapi.h>
#include <sstream>
#include "EntryPointParameter.h"
#include "CrashHandler.h"

// Global Variables
CoreCLR* CLR = nullptr;
HMODULE thisProcessModule = nullptr;
EntryPointParameters entryPointParameters;
string_t launcherPath;

// Function Prototypes
string_t get_current_directory(HMODULE hModule);
DWORD __fastcall InjectPayloadAndExecute(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPCVOID lpBuffer, SIZE_T dwSize);
LPSTR ToLPCSTR(LPWSTR wstr);

/* Entry point */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    launcherPath = get_current_directory(hModule);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        thisProcessModule = hModule;
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

// Helper function to get the current directory of the module
string_t get_current_directory(HMODULE mHandle) {
    wchar_t host_path[MAX_PATH] = { 0 };
    GetModuleFileNameW(mHandle, host_path, MAX_PATH);
    string_t root_path = host_path;
    return root_path.substr(0, root_path.find_last_of(L'\\') + 1);
}

// Function to inject a payload and execute it remotely
DWORD __fastcall InjectPayloadAndExecute(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPCVOID lpBuffer, SIZE_T dwSize) {
    void* allocatedMemory = nullptr;
    HANDLE remoteThread;
    DWORD exitCode = 0;

    if (lpBuffer && dwSize) {
        allocatedMemory = VirtualAllocEx(hProcess, nullptr, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (allocatedMemory) {
            WriteProcessMemory(hProcess, allocatedMemory, lpBuffer, dwSize, nullptr);
        }
        else {
            MessageBoxA(nullptr, "Failed to Inject Payload.", "Failed", MB_OK);
            return GetLastError();
        }
    }

    remoteThread = CreateRemoteThread(hProcess, nullptr, 0, lpStartAddress, allocatedMemory, 0, nullptr);
    if (remoteThread) {
        WaitForSingleObject(remoteThread, INFINITE);
        GetExitCodeThread(remoteThread, &exitCode);
    }
    else {
        MessageBoxA(nullptr, "Failed to create remote thread.", "Failed", MB_OK);
        return GetLastError();
    }

    if (allocatedMemory) {
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
    }

    if (remoteThread) {
        CloseHandle(remoteThread);
    }

    return exitCode;
}

// Convert wide string to C-style string
LPSTR ToLPCSTR(LPWSTR wstr) {
    std::wstring ws(wstr);
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    std::string str = converter.to_bytes(ws);
    return _strdup(str.c_str());
}

extern "C" __declspec(dllexport) void InitNativeCrashHandler() {
    CrashHandler::getInstance().initialize(launcherPath);
}

// Exported function to bootstrap the CoreCLR runtime and load the target .NET assembly
extern "C" __declspec(dllexport) void Bootstrap() {
    CrashHandler::getInstance().initialize(launcherPath);

    int success = 0;
    CLR = new CoreCLR(&success);

    if (!success) {
        MessageBoxA(nullptr, "Failed to load the `hostfxr` library. Did you copy nethost.dll?", "Failed", MB_OK);
        return;
    }

    if (!CLR->load_runtime(launcherPath + L"Chorizite.Launcher.runtimeconfig.json")) {
        MessageBoxA(nullptr, "Failed to load .NET Core Runtime", "Failed", MB_OK);
        throw std::exception("Failed to load .NET Core Runtime");
    }

    const string_t assembly_path = launcherPath + L"Chorizite.NativeClientBootstrapper.dll";
    const string_t type_name = L"Chorizite.NativeClientBootstrapper.StandaloneLoader, Chorizite.NativeClientBootstrapper";
    const string_t method_name = L"Init";
    component_entry_point_fn initialize = nullptr;

    if (!CLR->load_assembly_and_get_function_pointer(assembly_path.c_str(), type_name.c_str(), method_name.c_str(), nullptr, nullptr, (void**)&initialize)) {
        MessageBoxA(nullptr, "Failed to load .NET assembly.", "Failed", MB_OK);
        return;
    }

    entryPointParameters.dll_path = new wchar_t[MAX_PATH];
    GetModuleFileNameW(thisProcessModule, entryPointParameters.dll_path, MAX_PATH);
    initialize(&entryPointParameters, sizeof(EntryPointParameters));
}

// Launch the injected payload and execute entry points in the target process
extern "C" __declspec(dllexport) DWORD LaunchInjected(wchar_t* source, LPCWSTR lpCurrentDirectory, EntryPointParameters* entryPointParameters, int numParams) {
    if (!source || !lpCurrentDirectory) return 0;

    STARTUPINFOW startupInfo = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION processInfo = { 0 };

    std::unique_ptr<wchar_t[]> cmdLine(new wchar_t[wcslen(source) + 1]);
    wcscpy_s(cmdLine.get(), wcslen(source) + 1, source);

    if (!CreateProcessW(nullptr, cmdLine.get(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, lpCurrentDirectory, &startupInfo, &processInfo)) {
        MessageBoxW(nullptr, L"Failed", L"Failed to create process", MB_OK);
        return 0;
    }

    HMODULE kernelModule = GetModuleHandleW(L"kernel32.dll");

    if (!kernelModule) {
		MessageBoxW(nullptr, L"Failed", L"Failed to load kernel32.dll", MB_OK);
		return 0;
	}

    auto loadLibraryW = reinterpret_cast<HMODULE(__stdcall*)(LPCWSTR)>(GetProcAddress(kernelModule, "LoadLibraryW"));

    for (int i = 0; i < numParams; i++) {
        wchar_t* injectedLibName = entryPointParameters[i].dll_path;
        InjectPayloadAndExecute(processInfo.hProcess, (LPTHREAD_START_ROUTINE)loadLibraryW, injectedLibName, 2 * wcslen(injectedLibName));
        HMODULE loadedLibrary = ::LoadLibraryW(injectedLibName);

        char procName[200] = { 0 };
        sprintf_s(procName, "%S", entryPointParameters[i].entry_point);

        if (!loadedLibrary) {
			MessageBoxW(nullptr, L"Failed", L"Failed to load library", MB_OK);
			return 0;
		}

        LPVOID procAddress = GetProcAddress(loadedLibrary, procName);
        InjectPayloadAndExecute(processInfo.hProcess, (LPTHREAD_START_ROUTINE)procAddress, nullptr, 0);
        FreeLibrary(loadedLibrary);
    }

    ResumeThread(processInfo.hThread);
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
    return processInfo.dwProcessId;
}
