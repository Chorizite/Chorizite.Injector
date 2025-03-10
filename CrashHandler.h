// CrashHandler.h
#pragma once

#include <Windows.h>
#include <DbgHelp.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>

#pragma comment(lib, "Dbghelp.lib")

// Forward declaration for .NET integration
namespace Microsoft {
    namespace Diagnostics {
        namespace Runtime {}
    }
}

class CrashHandler {
public:
    static CrashHandler& getInstance() {
        static CrashHandler instance;
        return instance;
    }

    bool initialize(const std::wstring& dumpPath);
    void shutdown();

    // Settings
    void setSymbolPath(const std::wstring& symbolPath);
    void enableFullMemoryDump(bool enable);
    void enableAutomaticReporting(bool enable);

    // For .NET integration
    void registerManagedCallbacks();

    // Function pointer type for the .NET symbol resolver
    typedef const char* (*ManagedSymbolResolverFunc)(DWORD64 address);

    // Pointer to the managed resolver function
    ManagedSymbolResolverFunc m_managedResolver;

    // Buffer for the managed symbol result
    char m_managedSymbolBuffer[1024];

    // Track if the .NET resolver is available
    bool m_dotNetResolverAvailable;

    // Function pointer type for the .NET symbol resolver
    typedef const char* (*ManagedExtraInfoResolverFunc)();

    // Pointer to the managed resolver function
    ManagedExtraInfoResolverFunc m_managedExtraInfoResolver;

    // Buffer for the managed symbol result
    char m_managedExtraBuffer[1024];

    // Track if the .NET resolver is available
    bool m_dotNetExtraInfoResolverAvailable;

    // In CrashHandler.cpp, update the constructor to initialize new members
    CrashHandler();
    ~CrashHandler();

    // No copy or move
    CrashHandler(const CrashHandler&) = delete;
    CrashHandler& operator=(const CrashHandler&) = delete;
    CrashHandler(CrashHandler&&) = delete;
    CrashHandler& operator=(CrashHandler&&) = delete;

    // Exception handling
    static LONG WINAPI unhandledExceptionFilter(EXCEPTION_POINTERS* exceptionPointers);
    static LONG WINAPI vectoredExceptionHandler(EXCEPTION_POINTERS* exceptionPointers);
    void handleException(EXCEPTION_POINTERS* exceptionPointers);

    // Symbol resolution
    bool initializeSymbols();
    std::string resolveSymbol(DWORD64 address);

    // Stack walking
    std::vector<std::string> captureStackTrace(CONTEXT* context);

    // .NET specific functionality
    void handleManagedException(void* exception);
    std::vector<std::string> captureManagedStackTrace(void* exception);

    // Add a method to register the .NET symbol resolver
    void registerManagedSymbolResolver(ManagedSymbolResolverFunc resolver);

    // Add a method to register the .NET symbol resolver
    void registerManagedExtraInfoResolver(ManagedExtraInfoResolverFunc resolver);

    // Internal state
    std::wstring m_dumpPath;
    std::wstring m_symbolPath;
    bool m_symbolsInitialized;
    bool m_fullMemoryDump;
    bool m_autoReport;
    std::mutex m_crashHandlerMutex;

    // Previous exception filter
    LPTOP_LEVEL_EXCEPTION_FILTER m_previousFilter;
    void* m_vectoredExceptionHandle;

    // .NET integration
    void* m_appDomainCallbackToken;
};

// Helper for C# code to access the crash handler
extern "C" __declspec(dllexport) void RegisterManagedCrashHandler();