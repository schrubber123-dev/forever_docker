// Diagnostic instrumentation only. No endpoint, authentication or product-state override.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <tlhelp32.h>
#include <MinHook.h>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cstdint>

#ifndef FOREVER_DIAGNOSTIC_REVISION
#define FOREVER_DIAGNOSTIC_REVISION "local"
#endif

namespace {
HMODULE gModule = nullptr;
HANDLE gLog = INVALID_HANDLE_VALUE;
SRWLOCK gLogLock = SRWLOCK_INIT;
SRWLOCK gLifecycleLock = SRWLOCK_INIT;
std::atomic<bool> gEnabled{false};
std::atomic<bool> gStopRequested{false};
// 0 initializing, 1 ready, 2 stopping, 3 stopped, 4 initialization failed.
std::atomic<int> gState{0};
thread_local bool gInsideHook = false;
DWORD gWritten = 0;
bool gLogCapped = false;
constexpr DWORD LogLimit = 8 * 1024 * 1024;
struct HookAudit { const char* name; void* target; };
HookAudit gAudits[16]{};
size_t gAuditCount = 0;

struct Errors {
    DWORD win;
    int wsa;
    static Errors Get() noexcept {
        const DWORD win = GetLastError();
        const int wsa = WSAGetLastError();
        return {win, wsa};
    }
    void Restore() const noexcept { WSASetLastError(wsa); SetLastError(win); }
};

void Log(const char* format, ...) noexcept {
    char body[6200]{};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(body, sizeof(body), _TRUNCATE, format, args);
    va_end(args);
    SYSTEMTIME utc{};
    GetSystemTime(&utc);
    char line[6600]{};
    _snprintf_s(line, sizeof(line), _TRUNCATE,
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ pid=%lu tid=%lu %s\r\n",
        utc.wYear, utc.wMonth, utc.wDay, utc.wHour, utc.wMinute,
        utc.wSecond, utc.wMilliseconds, GetCurrentProcessId(), GetCurrentThreadId(), body);
    const DWORD length = static_cast<DWORD>(strlen(line));
    AcquireSRWLockExclusive(&gLogLock);
    if (gLog != INVALID_HANDLE_VALUE && !gLogCapped) {
        DWORD actual = 0;
        if (gWritten + length <= LogLimit) {
            if (WriteFile(gLog, line, length, &actual, nullptr)) gWritten += actual;
        } else {
            constexpr char cap[] = "TRACE_LOG_LIMIT_REACHED; further metadata omitted\r\n";
            if (gWritten + sizeof(cap) - 1 <= LogLimit)
                WriteFile(gLog, cap, sizeof(cap) - 1, &actual, nullptr);
            gLogCapped = true;
        }
    }
    ReleaseSRWLockExclusive(&gLogLock);
}

void FinishLog() noexcept {
    AcquireSRWLockExclusive(&gLogLock);
    if (gLog != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(gLog);
        CloseHandle(gLog);
        gLog = INVALID_HANDLE_VALUE;
    }
    ReleaseSRWLockExclusive(&gLogLock);
}

// Keep SEH in a plain helper, without C++ objects requiring stack unwinding.
bool ReadAddress(const sockaddr* address, int length, sockaddr_storage* copy) noexcept {
    if (!address || length < static_cast<int>(sizeof(ADDRESS_FAMILY))) return false;
    __try {
        const size_t n = static_cast<size_t>(length) < sizeof(*copy) ? static_cast<size_t>(length) : sizeof(*copy);
        memcpy(copy, address, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool ReadCodeWindow(const void* address, unsigned char* out) noexcept {
    __try { memcpy(out, static_cast<const unsigned char*>(address) - 8, 24); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

void Audit(const char* phase, const char* name, void* target) noexcept {
    MEMORY_BASIC_INFORMATION info{};
    const auto pc = reinterpret_cast<uintptr_t>(target);
    const auto base = VirtualQuery(target, &info, sizeof(info)) ? reinterpret_cast<uintptr_t>(info.AllocationBase) : 0;
    unsigned char bytes[24]{};
    char hex[49]{};
    if (ReadCodeWindow(target, bytes)) {
        for (size_t i = 0; i < sizeof(bytes); ++i) _snprintf_s(hex + 2 * i, sizeof(hex) - 2 * i, _TRUNCATE, "%02X", bytes[i]);
    } else { strcpy_s(hex, "unreadable"); }
    Log("HOOK_AUDIT phase=%s name=%s address=0x%llX moduleBase=0x%llX rva=0x%llX codeWindowOffset=-8 codeWindowLength=24 bytes=%s",
        phase, name, static_cast<unsigned long long>(pc), static_cast<unsigned long long>(base),
        static_cast<unsigned long long>(base ? pc - base : 0), hex);
}

void AddressText(const sockaddr* address, int length, char* out, size_t capacity) noexcept {
    sockaddr_storage copy{};
    if (!ReadAddress(address, length, &copy)) {
        _snprintf_s(out, capacity, _TRUNCATE, "unreadable(len=%d)", length);
        return;
    }
    char ip[INET6_ADDRSTRLEN]{};
    if (copy.ss_family == AF_INET && length >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto* a = reinterpret_cast<const sockaddr_in*>(&copy);
        if (InetNtopA(AF_INET, const_cast<IN_ADDR*>(&a->sin_addr), ip, sizeof(ip))) {
            _snprintf_s(out, capacity, _TRUNCATE, "family=2,address=%s,port=%u", ip, ntohs(a->sin_port));
            return;
        }
    } else if (copy.ss_family == AF_INET6 && length >= static_cast<int>(sizeof(sockaddr_in6))) {
        const auto* a = reinterpret_cast<const sockaddr_in6*>(&copy);
        if (InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&a->sin6_addr), ip, sizeof(ip))) {
            _snprintf_s(out, capacity, _TRUNCATE, "family=23,address=%s,port=%u,scope=%lu", ip, ntohs(a->sin6_port), a->sin6_scope_id);
            return;
        }
    }
    _snprintf_s(out, capacity, _TRUNCATE, "family=%u,len=%d", copy.ss_family, length);
}

void Stack() noexcept {
    void* frames[16]{};
    const USHORT count = CaptureStackBackTrace(1, 16, frames, nullptr);
    char text[3800]{};
    size_t used = 0;
    for (USHORT i = 0; i < count && used + 180 < sizeof(text); ++i) {
        MEMORY_BASIC_INFORMATION info{};
        const auto pc = reinterpret_cast<uintptr_t>(frames[i]);
        const auto base = VirtualQuery(frames[i], &info, sizeof(info)) ? reinterpret_cast<uintptr_t>(info.AllocationBase) : 0;
        const int n = _snprintf_s(text + used, sizeof(text) - used, _TRUNCATE,
            " frame%u=0x%llX(base=0x%llX,rva=0x%llX)", i,
            static_cast<unsigned long long>(pc), static_cast<unsigned long long>(base),
            static_cast<unsigned long long>(base ? pc - base : 0));
        if (n < 0) break;
        used += static_cast<size_t>(n);
    }
    Log("STACK%s", text);
}

void Modules() noexcept {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) { Log("MODULE_MAP_FAILED Win32Error=%lu", GetLastError()); return; }
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    BOOL more = Module32FirstW(snapshot, &entry);
    unsigned count = 0;
    while (more && count++ < 2048) {
        char name[1024]{};
        WideCharToMultiByte(CP_UTF8, 0, entry.szModule, -1, name, sizeof(name), nullptr, nullptr);
        Log("MODULE name=%s base=0x%llX size=0x%lX", name,
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(entry.modBaseAddr)), entry.modBaseSize);
        more = Module32NextW(snapshot, &entry);
    }
    CloseHandle(snapshot);
}

decltype(&::socket) RealSocket = nullptr;
decltype(&::WSASocketW) RealWSASocketW = nullptr;
decltype(&::WSASocketA) RealWSASocketA = nullptr;
decltype(&::connect) RealConnect = nullptr;
decltype(&::WSAConnect) RealWSAConnect = nullptr;
decltype(&::bind) RealBind = nullptr;
decltype(&::ioctlsocket) RealIoctlSocket = nullptr;
decltype(&::WSAIoctl) RealWSAIoctl = nullptr;
decltype(&::setsockopt) RealSetSockOpt = nullptr;
decltype(&::closesocket) RealCloseSocket = nullptr;
LPFN_CONNECTEX RealConnectEx = nullptr;

// Every callback restores pre-call error state before the real API, and post-call
// state after diagnostics. Successful APIs can leave last-error unchanged.
#define TRACE_BEGIN(original, call) \
    const Errors before = Errors::Get(); \
    if (gInsideHook || !gEnabled.load(std::memory_order_acquire)) { before.Restore(); return original call; } \
    gInsideHook = true; \
    before.Restore()
#define TRACE_END(value) \
    gInsideHook = false; \
    after.Restore(); \
    return value

SOCKET WSAAPI HookSocket(int family, int type, int protocol) {
    TRACE_BEGIN(RealSocket, (family, type, protocol));
    const SOCKET result = RealSocket(family, type, protocol);
    const Errors after = Errors::Get();
    Log("API=socket family=%d type=%d protocol=%d return=0x%llX WSAError=%d Win32Error=%lu", family, type, protocol, static_cast<unsigned long long>(result), after.wsa, after.win);
    TRACE_END(result);
}
SOCKET WSAAPI HookWSASocketW(int family, int type, int protocol, LPWSAPROTOCOL_INFOW info, GROUP group, DWORD flags) {
    TRACE_BEGIN(RealWSASocketW, (family, type, protocol, info, group, flags));
    const SOCKET result = RealWSASocketW(family, type, protocol, info, group, flags);
    const Errors after = Errors::Get();
    Log("API=WSASocketW family=%d type=%d protocol=%d flags=0x%lX return=0x%llX WSAError=%d Win32Error=%lu", family, type, protocol, flags, static_cast<unsigned long long>(result), after.wsa, after.win);
    TRACE_END(result);
}
SOCKET WSAAPI HookWSASocketA(int family, int type, int protocol, LPWSAPROTOCOL_INFOA info, GROUP group, DWORD flags) {
    TRACE_BEGIN(RealWSASocketA, (family, type, protocol, info, group, flags));
    const SOCKET result = RealWSASocketA(family, type, protocol, info, group, flags);
    const Errors after = Errors::Get();
    Log("API=WSASocketA family=%d type=%d protocol=%d flags=0x%lX return=0x%llX WSAError=%d Win32Error=%lu", family, type, protocol, flags, static_cast<unsigned long long>(result), after.wsa, after.win);
    TRACE_END(result);
}
int WSAAPI HookConnect(SOCKET socket, const sockaddr* address, int length) {
    TRACE_BEGIN(RealConnect, (socket, address, length));
    const int result = RealConnect(socket, address, length);
    const Errors after = Errors::Get();
    char endpoint[200]{}; AddressText(address, length, endpoint, sizeof(endpoint));
    Log("API=connect socket=0x%llX %s return=%d WSAError=%d Win32Error=%lu", static_cast<unsigned long long>(socket), endpoint, result, after.wsa, after.win);
    Stack();
    TRACE_END(result);
}
int WSAAPI HookWSAConnect(SOCKET socket, const sockaddr* address, int length, LPWSABUF caller, LPWSABUF callee, LPQOS sendQos, LPQOS recvQos) {
    TRACE_BEGIN(RealWSAConnect, (socket, address, length, caller, callee, sendQos, recvQos));
    const int result = RealWSAConnect(socket, address, length, caller, callee, sendQos, recvQos);
    const Errors after = Errors::Get();
    char endpoint[200]{}; AddressText(address, length, endpoint, sizeof(endpoint));
    Log("API=WSAConnect socket=0x%llX %s return=%d WSAError=%d Win32Error=%lu", static_cast<unsigned long long>(socket), endpoint, result, after.wsa, after.win);
    Stack();
    TRACE_END(result);
}
BOOL PASCAL HookConnectEx(SOCKET socket, const sockaddr* address, int length, PVOID sendBuffer, DWORD sendLength, LPDWORD sent, LPOVERLAPPED overlapped) {
    TRACE_BEGIN(RealConnectEx, (socket, address, length, sendBuffer, sendLength, sent, overlapped));
    const BOOL result = RealConnectEx(socket, address, length, sendBuffer, sendLength, sent, overlapped);
    const Errors after = Errors::Get();
    char endpoint[200]{}; AddressText(address, length, endpoint, sizeof(endpoint));
    Log("API=ConnectEx socket=0x%llX %s return=%d WSAError=%d Win32Error=%lu", static_cast<unsigned long long>(socket), endpoint, result, after.wsa, after.win);
    Stack();
    TRACE_END(result);
}
int WSAAPI HookBind(SOCKET socket, const sockaddr* address, int length) {
    TRACE_BEGIN(RealBind, (socket, address, length));
    const int result = RealBind(socket, address, length);
    const Errors after = Errors::Get();
    char endpoint[200]{}; AddressText(address, length, endpoint, sizeof(endpoint));
    Log("API=bind socket=0x%llX %s return=%d WSAError=%d Win32Error=%lu", static_cast<unsigned long long>(socket), endpoint, result, after.wsa, after.win);
    TRACE_END(result);
}
int WSAAPI HookIoctlSocket(SOCKET socket, long command, u_long* value) {
    TRACE_BEGIN(RealIoctlSocket, (socket, command, value));
    const int result = RealIoctlSocket(socket, command, value);
    const Errors after = Errors::Get();
    Log("API=ioctlsocket socket=0x%llX command=0x%lX return=%d WSAError=%d Win32Error=%lu", static_cast<unsigned long long>(socket), static_cast<unsigned long>(command), result, after.wsa, after.win);
    TRACE_END(result);
}
int WSAAPI HookWSAIoctl(SOCKET socket, DWORD code, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize, LPDWORD bytes, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    TRACE_BEGIN(RealWSAIoctl, (socket, code, inBuffer, inSize, outBuffer, outSize, bytes, overlapped, completion));
    const int result = RealWSAIoctl(socket, code, inBuffer, inSize, outBuffer, outSize, bytes, overlapped, completion);
    const Errors after = Errors::Get();
    Log("API=WSAIoctl socket=0x%llX code=0x%lX return=%d WSAError=%d Win32Error=%lu", static_cast<unsigned long long>(socket), code, result, after.wsa, after.win);
    TRACE_END(result);
}
int WSAAPI HookSetSockOpt(SOCKET socket, int level, int option, const char* value, int length) {
    TRACE_BEGIN(RealSetSockOpt, (socket, level, option, value, length));
    const int result = RealSetSockOpt(socket, level, option, value, length);
    const Errors after = Errors::Get();
    Log("API=setsockopt socket=0x%llX level=%d option=%d length=%d return=%d WSAError=%d Win32Error=%lu", static_cast<unsigned long long>(socket), level, option, length, result, after.wsa, after.win);
    TRACE_END(result);
}
int WSAAPI HookCloseSocket(SOCKET socket) {
    TRACE_BEGIN(RealCloseSocket, (socket));
    const int result = RealCloseSocket(socket);
    const Errors after = Errors::Get();
    Log("API=closesocket socket=0x%llX beforeWSAError=%d beforeWin32Error=%lu return=%d WSAError=%d Win32Error=%lu", static_cast<unsigned long long>(socket), before.wsa, before.win, result, after.wsa, after.win);
    Stack();
    TRACE_END(result);
}
#undef TRACE_BEGIN
#undef TRACE_END

bool Hook(HMODULE module, const char* name, void* detour, void** original) noexcept {
    void* address = reinterpret_cast<void*>(GetProcAddress(module, name));
    if (!address) { Log("HOOK_FAILED name=%s missing-export Win32Error=%lu", name, GetLastError()); return false; }
    Audit("before", name, address);
    const MH_STATUS status = MH_CreateHook(address, detour, original);
    Log("HOOK name=%s address=0x%llX status=%d", name, static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(address)), status);
    if (status == MH_OK && gAuditCount < sizeof(gAudits) / sizeof(gAudits[0])) gAudits[gAuditCount++] = {name, address};
    return status == MH_OK;
}

void StopReadyTrace() noexcept {
    gStopRequested.store(true, std::memory_order_release);
    AcquireSRWLockExclusive(&gLifecycleLock);
    if (gState.load() != 1) { ReleaseSRWLockExclusive(&gLifecycleLock); return; }
    gState.store(2);
    gEnabled.store(false, std::memory_order_release);
    const MH_STATUS status = MH_DisableHook(MH_ALL_HOOKS);
    for (size_t i = 0; i < gAuditCount; ++i) Audit("restored", gAudits[i].name, gAudits[i].target);
    Modules();
    Log("TRACE_STOPPED disableStatus=%d; trampolines and module retained until process exit", status);
    FinishLog();
    gState.store(3, std::memory_order_release);
    ReleaseSRWLockExclusive(&gLifecycleLock);
}

DWORD WINAPI Worker(void*) {
    // Pin this diagnostic module: never unload code or trampolines while a callback may run.
    HMODULE pinned = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(&Worker), &pinned);
    wchar_t path[32768]{};
    const DWORD n = GetModuleFileNameW(gModule, path, static_cast<DWORD>(sizeof(path) / sizeof(path[0])));
    if (!n || n >= sizeof(path) / sizeof(path[0])) { gState.store(4); return 1; }
    wchar_t* slash = wcsrchr(path, L'\\');
    if (!slash) { gState.store(4); return 1; }
    const size_t remaining = (sizeof(path) / sizeof(path[0])) - static_cast<size_t>(slash + 1 - path);
    _snwprintf_s(slash + 1, remaining, _TRUNCATE, L"socket-%lu.log", GetCurrentProcessId());
    gLog = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (gLog == INVALID_HANDLE_VALUE) { gState.store(4); return 1; }
    Log("TRACE_START revision=%s; numeric socket metadata only; default provider ConnectEx coverage; no buffers, credentials or environment", FOREVER_DIAGNOSTIC_REVISION);
    Modules();
    HMODULE ws = LoadLibraryW(L"ws2_32.dll");
    if (!ws) { Log("TRACE_FAILED ws2_32 load Win32Error=%lu", GetLastError()); FinishLog(); gState.store(4); return 1; }

    // Query a default-provider extension before hooks are enabled. Balance only our WSA reference.
    LPFN_CONNECTEX extension = nullptr;
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) == 0) {
        const SOCKET socket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (socket != INVALID_SOCKET) {
            GUID id = WSAID_CONNECTEX;
            DWORD bytes = 0;
            WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &extension, sizeof(extension), &bytes, nullptr, nullptr);
            closesocket(socket);
        }
        WSACleanup();
    }
    if (MH_Initialize() != MH_OK) { Log("TRACE_FAILED MinHook initialization"); FinishLog(); gState.store(4); return 1; }
    bool okay = true;
    okay = Hook(ws, "socket", reinterpret_cast<void*>(&HookSocket), reinterpret_cast<void**>(&RealSocket)) && okay;
    // Explicit names keep capitalization of Win32 exports and C++ callback names independent.
    okay = Hook(ws, "WSASocketW", reinterpret_cast<void*>(&HookWSASocketW), reinterpret_cast<void**>(&RealWSASocketW)) && okay;
    okay = Hook(ws, "WSASocketA", reinterpret_cast<void*>(&HookWSASocketA), reinterpret_cast<void**>(&RealWSASocketA)) && okay;
    okay = Hook(ws, "connect", reinterpret_cast<void*>(&HookConnect), reinterpret_cast<void**>(&RealConnect)) && okay;
    okay = Hook(ws, "WSAConnect", reinterpret_cast<void*>(&HookWSAConnect), reinterpret_cast<void**>(&RealWSAConnect)) && okay;
    okay = Hook(ws, "bind", reinterpret_cast<void*>(&HookBind), reinterpret_cast<void**>(&RealBind)) && okay;
    okay = Hook(ws, "ioctlsocket", reinterpret_cast<void*>(&HookIoctlSocket), reinterpret_cast<void**>(&RealIoctlSocket)) && okay;
    okay = Hook(ws, "WSAIoctl", reinterpret_cast<void*>(&HookWSAIoctl), reinterpret_cast<void**>(&RealWSAIoctl)) && okay;
    okay = Hook(ws, "setsockopt", reinterpret_cast<void*>(&HookSetSockOpt), reinterpret_cast<void**>(&RealSetSockOpt)) && okay;
    okay = Hook(ws, "closesocket", reinterpret_cast<void*>(&HookCloseSocket), reinterpret_cast<void**>(&RealCloseSocket)) && okay;
    if (extension) {
        Audit("before", "ConnectEx-default-provider", reinterpret_cast<void*>(extension));
        const MH_STATUS ex = MH_CreateHook(reinterpret_cast<void*>(extension), reinterpret_cast<void*>(&HookConnectEx), reinterpret_cast<void**>(&RealConnectEx));
        Log("HOOK name=ConnectEx-default-provider status=%d", ex);
        okay = okay && ex == MH_OK;
        if (ex == MH_OK && gAuditCount < sizeof(gAudits) / sizeof(gAudits[0])) gAudits[gAuditCount++] = {"ConnectEx-default-provider", reinterpret_cast<void*>(extension)};
    } else { Log("COVERAGE ConnectEx-default-provider unavailable; ConnectEx calls may not be observed"); }
    AcquireSRWLockExclusive(&gLifecycleLock);
    if (!okay || gStopRequested.load() || MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        MH_DisableHook(MH_ALL_HOOKS);
        Log("TRACE_FAILED required hook creation/enable or stop requested during initialization");
        FinishLog();
        gState.store(4);
        ReleaseSRWLockExclusive(&gLifecycleLock);
        return 1;
    }
    gEnabled.store(true, std::memory_order_release);
    gState.store(1, std::memory_order_release);
    for (size_t i = 0; i < gAuditCount; ++i) Audit("instrumented", gAudits[i].name, gAudits[i].target);
    Log("TRACE_READY hooks=socket,WSASocketW,WSASocketA,connect,WSAConnect,bind,ioctlsocket,WSAIoctl,setsockopt,closesocket ConnectEx=%s", extension ? "default-provider" : "unavailable");
    ReleaseSRWLockExclusive(&gLifecycleLock);
    const ULONGLONG deadline = GetTickCount64() + 120000;
    while (GetTickCount64() < deadline && !gStopRequested.load(std::memory_order_acquire)) Sleep(100);
    StopReadyTrace();
    return 0;
}
} // namespace

extern "C" __declspec(dllexport) DWORD WINAPI ForeverTraceStop(void*) {
    StopReadyTrace();
    return static_cast<DWORD>(gState.load(std::memory_order_acquire));
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        gModule = instance;
        // Static CRT requires thread notifications; do not call DisableThreadLibraryCalls.
        HANDLE thread = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    }
    // Do not invoke MinHook, wait on threads or unload from the loader-lock context.
    return TRUE;
}
