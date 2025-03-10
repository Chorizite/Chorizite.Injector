// CrashHandler.cpp
#include "pch.h"
#include "CrashHandler.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
// For .NET integration
#include <metahost.h>
#include <mscoree.h>

#pragma comment(lib, "mscoree.lib")

// Global instance for callbacks
CrashHandler* g_crashHandlerInstance = nullptr;
bool didError = false;

CrashHandler::CrashHandler()
    : m_symbolsInitialized(false)
    , m_fullMemoryDump(true)
    , m_autoReport(false)
    , m_previousFilter(nullptr)
    , m_vectoredExceptionHandle(nullptr)
    , m_appDomainCallbackToken(nullptr)
    , m_managedResolver(nullptr)
    , m_managedExtraInfoResolver(nullptr) 
    , m_dotNetResolverAvailable(false)
    , m_dotNetExtraInfoResolverAvailable(false)
{
    memset(m_managedSymbolBuffer, 0, sizeof(m_managedSymbolBuffer));
    memset(m_managedExtraBuffer, 0, sizeof(m_managedExtraBuffer));
    g_crashHandlerInstance = this;
}

CrashHandler::~CrashHandler() {
    shutdown();
    g_crashHandlerInstance = nullptr;
}

bool CrashHandler::initialize(const std::wstring& dumpPath) {
    std::lock_guard<std::mutex> lock(m_crashHandlerMutex);

    m_dumpPath = dumpPath;

    // Create dump directory if it doesn't exist
    //std::filesystem::create_directories(dumpPath);

    // Set up the symbol handler
    if (!initializeSymbols()) {
        return false;
    }

    // Set up exception handling
    m_previousFilter = SetUnhandledExceptionFilter(unhandledExceptionFilter);
    m_vectoredExceptionHandle = AddVectoredExceptionHandler(1, vectoredExceptionHandler);

    return true;
}

void CrashHandler::shutdown() {
    std::lock_guard<std::mutex> lock(m_crashHandlerMutex);

    // Restore previous exception handlers
    if (m_vectoredExceptionHandle) {
        RemoveVectoredExceptionHandler(m_vectoredExceptionHandle);
        m_vectoredExceptionHandle = nullptr;
    }

    if (m_previousFilter) {
        SetUnhandledExceptionFilter(m_previousFilter);
        m_previousFilter = nullptr;
    }

    // Clean up symbols
    if (m_symbolsInitialized) {
        SymCleanup(GetCurrentProcess());
        m_symbolsInitialized = false;
    }
}

void CrashHandler::setSymbolPath(const std::wstring& symbolPath) {
    std::lock_guard<std::mutex> lock(m_crashHandlerMutex);
    m_symbolPath = symbolPath;

    // Set up a default symbol path that includes:
    // 1. The module directory (where the executable is)
    // 2. Visual Studio's symbol cache
    std::wstring vsSymCache = L"C:\\Users\\";
    wchar_t userName[MAX_PATH];
    DWORD userNameSize = MAX_PATH;
    if (GetUserName(userName, &userNameSize)) {
        vsSymCache += userName;
        vsSymCache += L"\\AppData\\Local\\Temp\\SymbolCache";
    }
    // Get the module path where the application is running
    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);
    std::wstring moduleDir = modulePath;
    moduleDir = moduleDir.substr(0, moduleDir.find_last_of(L"\\/") + 1);

    // Use the module directory as part of the symbol path
    std::wstringstream symbolPathStream;
    symbolPathStream << moduleDir << L";"
        << m_symbolPath << L";"
        << vsSymCache << L";"
        << L"srv*https://msdl.microsoft.com/download/symbols";

    if (m_symbolsInitialized) {
        std::wstring symbolPathStr = symbolPathStream.str();
        char* symbolPathCStr = new char[symbolPathStr.length() + 1];
        wcstombs(symbolPathCStr, symbolPathStr.c_str(), symbolPathStr.length() + 1);
        SymSetSearchPath(GetCurrentProcess(), symbolPathCStr);
        delete[] symbolPathCStr;

        HMODULE hMod = GetModuleHandleW(L"xlua.dll");
        if (hMod == NULL) {
            return;
        }

        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(MODULEINFO))) {
            return;
        }

        SymLoadModuleExW(
            GetCurrentProcess(),
            NULL,
            L"xlua.dll",
            NULL,
            (DWORD64)modInfo.lpBaseOfDll,
            modInfo.SizeOfImage,
            NULL,
            0
        );
    }
}

// Add a method to register the .NET symbol resolver
void CrashHandler::registerManagedSymbolResolver(ManagedSymbolResolverFunc resolver) {
    m_managedResolver = resolver;
    m_dotNetResolverAvailable = (resolver != nullptr);
}

// Add a method to register the .NET symbol resolver
void CrashHandler::registerManagedExtraInfoResolver(ManagedExtraInfoResolverFunc resolver) {
    m_managedExtraInfoResolver = resolver;
    m_dotNetExtraInfoResolverAvailable = (resolver != nullptr);
}

std::string CrashHandler::resolveSymbol(DWORD64 address) {
    // First try to resolve using .NET host if available
    if (m_dotNetResolverAvailable && m_managedResolver) {
        // Call the managed resolver
        const char* managedSymbol = m_managedResolver(address);
        // If it returned a symbol, use it
        if (managedSymbol && managedSymbol[0] != '\0') {
            return std::string(managedSymbol);
        }
    }

    // If .NET resolver didn't work or isn't available, fall back to native resolver
    if (!m_symbolsInitialized) {
        std::stringstream result;
        result << "0x" << std::hex << address;
        MessageBoxA(nullptr, result.str().c_str(), "Failed m_symbolsInitialized", MB_OK);
        return result.str();
    }

    // Get module information
    IMAGEHLP_MODULE moduleInfo;
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE);
    std::string moduleName = "Unknown";

    if (SymGetModuleInfo(GetCurrentProcess(), address, &moduleInfo)) {
        moduleName = moduleInfo.ModuleName;
    }

    DWORD64 displacement = 0;
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO symbol = (PSYMBOL_INFO)buffer;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME;
    std::stringstream result;

    if (SymFromAddr(GetCurrentProcess(), address, &displacement, symbol)) {
        IMAGEHLP_LINE line;
        DWORD lineDisplacement = 0;
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE);
        if (SymGetLineFromAddr(GetCurrentProcess(), address, &lineDisplacement, &line)) {
            result << moduleName << "!" << symbol->Name << " at " << line.FileName << ":" << line.LineNumber;
        }
        else {
            result << moduleName << "!" << "0x" << std::hex << address << " " << symbol->Name << " + 0x" << std::hex << displacement;
        }
    }
    else {
        result << moduleName << "!" << "0x" << std::hex << address;
    }

    return result.str();
}

void CrashHandler::enableFullMemoryDump(bool enable) {
    m_fullMemoryDump = enable;
}

void CrashHandler::enableAutomaticReporting(bool enable) {
    m_autoReport = enable;
}

LONG WINAPI CrashHandler::unhandledExceptionFilter(EXCEPTION_POINTERS* exceptionPointers) {
    if (g_crashHandlerInstance) {
        g_crashHandlerInstance->handleException(exceptionPointers);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI CrashHandler::vectoredExceptionHandler(EXCEPTION_POINTERS* exceptionPointers) {
    // Only handle serious exceptions
    switch (exceptionPointers->ExceptionRecord->ExceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_BREAKPOINT:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_FLT_DENORMAL_OPERAND:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INEXACT_RESULT:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_UNDERFLOW:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
    case EXCEPTION_INVALID_DISPOSITION:
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_SINGLE_STEP:
    case EXCEPTION_STACK_OVERFLOW:
        if (g_crashHandlerInstance) {
            g_crashHandlerInstance->handleException(exceptionPointers);
        }
        break;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// Constants for dialog controls
#define IDC_TEXTAREA     1001
#define IDC_SEND_BUTTON  1002
#define IDC_CANCEL_BUTTON 1003

// Dialog procedure
LRESULT CALLBACK CrashDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_SEND_BUTTON:
            // Placeholder for future send functionality
            MessageBox(hDlg, L"Send report functionality will be implemented later.",
                L"Not Implemented", MB_ICONINFORMATION | MB_OK);
            return TRUE;

        case IDC_CANCEL_BUTTON:
            DestroyWindow(hDlg);
            return TRUE;
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hDlg, message, wParam, lParam);
}

void CrashHandler::handleException(EXCEPTION_POINTERS* exceptionPointers) {
    if (m_dotNetExtraInfoResolverAvailable == false) {
		return;
	}

    std::lock_guard<std::mutex> lock(m_crashHandlerMutex);

    // Prevent multiple crash dialogs
    if (didError) return;
    didError = true;

    // Capture and log the stack trace
    std::vector<std::string> stackTrace = captureStackTrace(exceptionPointers->ContextRecord);

    // Create a text report with the stack trace
    auto now = std::chrono::system_clock::now();
    auto timeT = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &timeT);

    std::wstringstream report;

    report << L"Exception Code: 0x" << std::hex << exceptionPointers->ExceptionRecord->ExceptionCode << std::dec << L"\r\n"
        << L"Exception Address: 0x" << std::hex << exceptionPointers->ExceptionRecord->ExceptionAddress << std::dec << L"\r\n\r\n";
    report << L"Stack Trace:\r\n";
    for (const auto& frame : stackTrace) {
        report << L"  " << frame.c_str() << L"\r\n";
    }

    /*
    report << "\r\nLoaded modules:\r\n";
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                IMAGEHLP_MODULE moduleInfo;
                moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE);
                bool symbolsLoaded = SymGetModuleInfo(hProcess, (DWORD64)hMods[i], &moduleInfo);

                report << szModName << " - Base: 0x" << std::hex << (DWORD64)hMods[i]
                    << " Symbols: " << (symbolsLoaded ? "Yes" : "No") << "\r\n";
            }
        }
    }
    */

    // append extra info if available
    if (m_dotNetExtraInfoResolverAvailable && m_managedExtraInfoResolver) {
        wchar_t* reportCStr = new wchar_t[report.str().length() + 1];
        wcscpy_s(reportCStr, report.str().length() + 1, report.str().c_str());
        char* reportCStrA = new char[report.str().length() * 2 + 1];
        size_t convertedChars;
        wcstombs_s(&convertedChars, reportCStrA, report.str().length() * 2 + 1, reportCStr, report.str().length() + 1);
        const char* managedExtraInfo = m_managedExtraInfoResolver();
        delete[] reportCStr;
        delete[] reportCStrA;

        if (managedExtraInfo && managedExtraInfo[0] != '\0') {
            report << managedExtraInfo;
        }
    }

    // Create the dialog
    HINSTANCE hInstance = GetModuleHandle(NULL);

    // Register the dialog class
    const wchar_t* className = L"CrashReportDialogClass";
    WNDCLASSEX wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = CrashDialogProc;
    wcex.hInstance = hInstance;
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszClassName = className;
    RegisterClassEx(&wcex);

    // Store the report text in a static variable for the dialog to access
    static std::wstring reportText = report.str();

    // Create and show the dialog
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int dialogWidth = 500;
    int dialogHeight = 400;
    int x = (screenWidth - dialogWidth) / 2;
    int y = (screenHeight - dialogHeight) / 2;

    HWND hDlg = CreateWindowEx(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        className,
        L"Application Crash Report",
        WS_VISIBLE | WS_POPUP | WS_CAPTION | WS_SYSMENU,
        x, y, dialogWidth, dialogHeight,
        NULL, NULL, hInstance, NULL);

    // Create label
    HWND hLabel = CreateWindowEx(
        0, L"STATIC", L"The application has crashed. Please send this report to help us fix the issue:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, 20, dialogWidth - 40, 40,
        hDlg, NULL, hInstance, NULL);

    // Create text area with proper line break handling
    HWND hTextArea = CreateWindowEx(
        WS_EX_CLIENTEDGE, L"EDIT", reportText.c_str(),
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        20, 70, dialogWidth - 40, dialogHeight - 150,
        hDlg, (HMENU)IDC_TEXTAREA, hInstance, NULL);

    // Set a monospaced font for better readability
    HFONT hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    SendMessage(hTextArea, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Create buttons
    HWND hSendButton = CreateWindowEx(
        0, L"BUTTON", L"Send Report",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        dialogWidth - 250, dialogHeight - 60, 100, 30,
        hDlg, (HMENU)IDC_SEND_BUTTON, hInstance, NULL);

    HWND hCancelButton = CreateWindowEx(
        0, L"BUTTON", L"Cancel",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        dialogWidth - 130, dialogHeight - 60, 100, 30,
        hDlg, (HMENU)IDC_CANCEL_BUTTON, hInstance, NULL);

    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

bool CrashHandler::initializeSymbols() {
    if (m_symbolsInitialized) {
        return true;
    }

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);

    // Set up a default symbol path that includes:
    // 1. The module directory (where the executable is)
    // 2. Visual Studio's symbol cache
    std::wstring vsSymCache = L"C:\\Users\\";
    wchar_t userName[MAX_PATH];
    DWORD userNameSize = MAX_PATH;
    if (GetUserName(userName, &userNameSize)) {
        vsSymCache += userName;
        vsSymCache += L"\\AppData\\Local\\Temp\\SymbolCache";
    }

    // Get the module path where the application is running
    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);
    std::wstring moduleDir = modulePath;
    moduleDir = moduleDir.substr(0, moduleDir.find_last_of(L"\\/") + 1);
    std::wstring  appDir = m_dumpPath;
    std::wstring  pluginsDir = appDir + L"plugins\\Lua\\runtimes\\win-x86\\native\\";

    std::wstringstream symbolPathStream;
    symbolPathStream << appDir.c_str() << L";"
        << moduleDir.c_str() << L";"
        << pluginsDir.c_str() << L";"
        << vsSymCache << L";"
        << L"srv*https://msdl.microsoft.com/download/symbols";


    std::wstring symbolPathStr = symbolPathStream.str();
    char* symbolPathCStr = new char[symbolPathStr.length() + 1];
    wcstombs(symbolPathCStr, symbolPathStr.c_str(), symbolPathStr.length() + 1);

    if (!SymInitialize(GetCurrentProcess(), symbolPathCStr, TRUE)) {
        MessageBoxA(nullptr, "Failed to initialize symbols.", symbolPathCStr, MB_OK);
        return false;
    }
    delete[] symbolPathCStr;
    m_symbolsInitialized = true;

    return true;
}

std::vector<std::string> CrashHandler::captureStackTrace(CONTEXT* context) {
    std::vector<std::string> stackTrace;

    STACKFRAME stackFrame;
    memset(&stackFrame, 0, sizeof(stackFrame));

#ifdef _M_IX86
    DWORD machineType = IMAGE_FILE_MACHINE_I386;
    stackFrame.AddrPC.Offset = context->Eip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context->Ebp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context->Esp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
#else
#error "Unsupported platform"
#endif

    for (int frameNum = 0; ; ++frameNum) {
        if (!StackWalk(
            machineType,
            GetCurrentProcess(),
            GetCurrentThread(),
            &stackFrame,
            context,
            nullptr,
            SymFunctionTableAccess,
            SymGetModuleBase,
            nullptr)) {
            break;
        }

        if (stackFrame.AddrPC.Offset == 0) {
            break;
        }

        std::stringstream frameDesc;
        frameDesc << "#" << frameNum << ": " << resolveSymbol(stackFrame.AddrPC.Offset);

        stackTrace.push_back(frameDesc.str());
    }

    return stackTrace;
}

// .NET integration methods
void CrashHandler::registerManagedCallbacks() {
    // This would be implemented using the CLR hosting APIs
    // Simplified implementation for illustration
    ICLRMetaHost* metaHost = nullptr;
    if (FAILED(CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (void**)&metaHost))) {
        return;
    }

    // This would attach to AppDomain.UnhandledException
    // Implementation would involve getting the runtime, getting the AppDomain,
    // and setting up event handlers

    metaHost->Release();
}

void CrashHandler::handleManagedException(void* exception) {
    // This would handle a managed exception
    // We would use the .NET metadata APIs to extract information

    // Capture managed stack trace
    std::vector<std::string> managedStack = captureManagedStackTrace(exception);

    // Log managed exception details
    // This would involve using ICorDebug or Microsoft.Diagnostics.Runtime
}

std::vector<std::string> CrashHandler::captureManagedStackTrace(void* exception) {
    std::vector<std::string> stackTrace;

    // This would use the Microsoft.Diagnostics.Runtime API
    // or ICorDebug to walk the managed stack

    // For a real implementation, this would involve:
    // 1. Attaching to the CLR
    // 2. Getting the thread where the exception occurred
    // 3. Walking the stack frames
    // 4. Resolving method names and source information from PDBs

    return stackTrace;
}



// Export for C# code
extern "C" __declspec(dllexport) void RegisterManagedCrashHandler() {
    if (g_crashHandlerInstance) {
        g_crashHandlerInstance->registerManagedCallbacks();
    }
}

// Add an export for registering the managed symbol resolver
extern "C" __declspec(dllexport) void RegisterManagedSymbolResolver(const char* (*resolverFunc)(DWORD64)) {
    if (g_crashHandlerInstance) {
        g_crashHandlerInstance->registerManagedSymbolResolver(resolverFunc);
    }
}

// Add an export for registering the managed extra info resolver
extern "C" __declspec(dllexport) void RegisterManagedExtraInfoResolver(const char* (*resolverFunc)()) {
	if (g_crashHandlerInstance) {
		g_crashHandlerInstance->registerManagedExtraInfoResolver(resolverFunc);
	}
}