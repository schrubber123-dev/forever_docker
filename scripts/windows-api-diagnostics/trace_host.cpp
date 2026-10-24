// Private-client diagnostics only: never starts or terminates WoW/Agent, never patches files.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <winver.h>
#include <bcrypt.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <regex>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "version.lib")
namespace fs = std::filesystem;
static_assert(sizeof(void*) == 8, "Build this diagnostic as x64.");

struct Handle {
    HANDLE h = nullptr;
    explicit Handle(HANDLE value = nullptr) : h(value) {}
    ~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    operator HANDLE() const { return h; }
};
[[noreturn]] void WinFail(const char* operation) {
    throw std::runtime_error(std::string(operation) + " failed, Win32=" + std::to_string(GetLastError()));
}
std::wstring Quote(const std::wstring& input) {
    std::wstring out = L"\""; size_t slashes = 0;
    for (wchar_t c : input) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'\"') out.append(slashes * 2 + 1, L'\\'); else out.append(slashes, L'\\');
        slashes = 0; out += c;
    }
    out.append(slashes * 2, L'\\'); return out + L"\"";
}
std::string Utc() {
    SYSTEMTIME s{}; GetSystemTime(&s); char out[64]{};
    sprintf_s(out, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", s.wYear,s.wMonth,s.wDay,s.wHour,s.wMinute,s.wSecond,s.wMilliseconds);
    return out;
}
fs::path ModulePath() {
    std::vector<wchar_t> path(32768);
    DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!size || size >= path.size()) WinFail("GetModuleFileNameW");
    return fs::path(std::wstring(path.data(), size));
}
fs::path Desktop() {
    PWSTR path = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, nullptr, &path))) throw std::runtime_error("Desktop folder unavailable.");
    fs::path out(path); CoTaskMemFree(path); return out;
}
std::wstring Unique() {
    GUID guid{}; if (FAILED(CoCreateGuid(&guid))) throw std::runtime_error("Cannot create unique run ID.");
    wchar_t out[40]{}; StringFromGUID2(guid, out, 40); return std::wstring(out + 1, 8);
}
fs::path RunFolder(const fs::path& root) {
    SYSTEMTIME t{}; GetLocalTime(&t); wchar_t stamp[64]{};
    swprintf_s(stamp,L"Forever-API-%04u%02u%02u-%02u%02u%02u-",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond);
    fs::path folder = root / (std::wstring(stamp) + Unique());
    if (!fs::create_directory(folder)) throw std::runtime_error("Output folder already exists.");
    return folder;
}
void Mark(const fs::path& folder, const std::string& text) {
    std::ofstream file(folder/L"markers.txt", std::ios::app|std::ios::binary);
    if (!file || !(file << Utc() << " " << text << "\r\n")) throw std::runtime_error("Cannot write diagnostic markers.");
}
std::string ReadText(const fs::path& file) {
    std::ifstream in(file, std::ios::binary); return std::string(std::istreambuf_iterator<char>(in), {});
}
std::string FileSha256(const fs::path& file) {
    BCRYPT_ALG_HANDLE algorithm=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;
    auto check=[](NTSTATUS code){if(code<0)throw std::runtime_error("SHA256 operation failed, NTSTATUS="+std::to_string(code));};
    try {
        check(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0));
        DWORD objectBytes=0,returned=0;
        check(BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&objectBytes),sizeof(objectBytes),&returned,0));
        std::vector<BYTE> object(objectBytes),buffer(1024*1024),digest(32);
        check(BCryptCreateHash(algorithm,&hash,object.data(),objectBytes,nullptr,0,0));
        std::ifstream input(file,std::ios::binary);if(!input)throw std::runtime_error("Cannot read target file for SHA256.");
        while(input){input.read(reinterpret_cast<char*>(buffer.data()),static_cast<std::streamsize>(buffer.size()));auto read=input.gcount();if(read>0)check(BCryptHashData(hash,buffer.data(),static_cast<ULONG>(read),0));}
        if(input.bad())throw std::runtime_error("Target file SHA256 read failed.");
        check(BCryptFinishHash(hash,digest.data(),static_cast<ULONG>(digest.size()),0));
        BCryptDestroyHash(hash);hash=nullptr;BCryptCloseAlgorithmProvider(algorithm,0);algorithm=nullptr;
        std::ostringstream text;for(BYTE value:digest)text<<std::hex<<std::setw(2)<<std::setfill('0')<<static_cast<unsigned>(value);return text.str();
    }catch(...){if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);throw;}
}

std::vector<DWORD> WowProcesses() {
    Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
    if (snap.h == INVALID_HANDLE_VALUE) WinFail("CreateToolhelp32Snapshot");
    PROCESSENTRY32W p{}; p.dwSize=sizeof(p); std::vector<DWORD> ids;
    if (!Process32FirstW(snap,&p)) { if (GetLastError()==ERROR_NO_MORE_FILES) return ids; WinFail("Process32FirstW"); }
    do { if (_wcsicmp(p.szExeFile,L"WowB.exe")==0) ids.push_back(p.th32ProcessID); } while (Process32NextW(snap,&p));
    if (GetLastError()!=ERROR_NO_MORE_FILES) WinFail("Process32NextW");
    return ids;
}
fs::path ImagePath(HANDLE process) {
    std::vector<wchar_t> path(32768); DWORD size=static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process,0,path.data(),&size)) WinFail("QueryFullProcessImageNameW");
    return fs::path(std::wstring(path.data(),size));
}
void ValidateWow(HANDLE process) {
    fs::path path=ImagePath(process);
    if (_wcsicmp(path.filename().c_str(),L"WowB.exe")!=0) throw std::runtime_error("Target is not WowB.exe.");
    BOOL wow64=FALSE;
    if (!IsWow64Process(process,&wow64)) WinFail("IsWow64Process");
    if (wow64) throw std::runtime_error("Only the x64 70450 client is supported.");
    DWORD ignored=0,size=GetFileVersionInfoSizeW(path.c_str(),&ignored);
    if (!size) WinFail("GetFileVersionInfoSizeW");
    std::vector<BYTE> bytes(size);
    if (!GetFileVersionInfoW(path.c_str(),0,size,bytes.data())) WinFail("GetFileVersionInfoW");
    VS_FIXEDFILEINFO* info=nullptr; UINT length=0;
    if (!VerQueryValueW(bytes.data(),L"\\",reinterpret_cast<void**>(&info),&length) || !info || length<sizeof(*info)) throw std::runtime_error("Client file version unavailable.");
    if (info->dwSignature!=0xFEEF04BD) throw std::runtime_error("Invalid client version metadata.");
    // The build exceeds 16 bits: fixed-file-info's fourth component alone cannot identify 70450.
    struct Translation { WORD language; WORD codepage; };
    Translation* languages=nullptr; UINT languageBytes=0; bool match=false;
    if (VerQueryValueW(bytes.data(),L"\\VarFileInfo\\Translation",reinterpret_cast<void**>(&languages),&languageBytes) && languages) {
        const std::wregex expected(LR"(^\s*1[.,]\s*60[.,]\s*1[.,]\s*70450(?:\s+.*|\s*\(.*\))?\s*$)");
        for (UINT i=0;i<languageBytes/sizeof(Translation);++i) {
            wchar_t key[80]{};swprintf_s(key,L"\\StringFileInfo\\%04x%04x\\FileVersion",languages[i].language,languages[i].codepage);
            wchar_t* value=nullptr;UINT count=0;
            if (VerQueryValueW(bytes.data(),key,reinterpret_cast<void**>(&value),&count) && value && count && std::regex_match(value,expected)) match=true;
        }
    }
    if (!match) throw std::runtime_error("FileVersion must identify exactly 1.60.1.70450; no DLL was injected.");
}
struct RemoteModule { uintptr_t base=0; DWORD size=0; };
RemoteModule FindModule(DWORD pid, const std::wstring& name, bool fullPath=false) {
    Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid));
    if (snap.h==INVALID_HANDLE_VALUE) return {};
    MODULEENTRY32W m{};m.dwSize=sizeof(m);
    if (Module32FirstW(snap,&m)) do {
        if (_wcsicmp(fullPath?m.szExePath:m.szModule,name.c_str())==0) return {reinterpret_cast<uintptr_t>(m.modBaseAddr),m.modBaseSize};
    } while (Module32NextW(snap,&m));
    return {};
}
uintptr_t RemoteLoadLibrary(DWORD pid) {
    auto local=reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"LoadLibraryW"));
    if (!local) WinFail("GetProcAddress LoadLibraryW");
    HMODULE owner=nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,reinterpret_cast<LPCWSTR>(local),&owner)) WinFail("GetModuleHandleExW");
    wchar_t ownerPath[32768]{};
    if (!GetModuleFileNameW(owner,ownerPath,32768)) WinFail("GetModuleFileNameW LoadLibrary owner");
    RemoteModule remote=FindModule(pid,fs::path(ownerPath).filename().wstring());
    uintptr_t rva=local-reinterpret_cast<uintptr_t>(owner);
    if (!remote.base || rva>=remote.size) throw std::runtime_error("Cannot map LoadLibraryW into target system module.");
    return remote.base+rva;
}
void Inject(HANDLE process,DWORD pid,const fs::path& dll) {
    size_t bytes=(dll.wstring().size()+1)*sizeof(wchar_t);
    void* remote=VirtualAllocEx(process,nullptr,bytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!remote) WinFail("VirtualAllocEx");
    SIZE_T written=0;
    if (!WriteProcessMemory(process,remote,dll.c_str(),bytes,&written) || written!=bytes) { VirtualFreeEx(process,remote,0,MEM_RELEASE);WinFail("WriteProcessMemory DLL path"); }
    uintptr_t loader=0;
    try { loader=RemoteLoadLibrary(pid); } catch (...) { VirtualFreeEx(process,remote,0,MEM_RELEASE);throw; }
    Handle thread(CreateRemoteThread(process,nullptr,0,reinterpret_cast<LPTHREAD_START_ROUTINE>(loader),remote,0,nullptr));
    if (!thread.h) { VirtualFreeEx(process,remote,0,MEM_RELEASE);WinFail("CreateRemoteThread LoadLibraryW"); }
    DWORD wait=WaitForSingleObject(thread,15000);
    // If a remote call is still running, leave its argument alive until process exit.
    if (wait!=WAIT_OBJECT_0) throw std::runtime_error("DLL load timed out; remote argument retained safely. Close WoW normally before retrying.");
    VirtualFreeEx(process,remote,0,MEM_RELEASE);
    if (!FindModule(pid,dll.wstring(),true).base) throw std::runtime_error("Diagnostic DLL was not loaded by target.");
}
void Stop(HANDLE process,DWORD pid,const fs::path& dll) {
    if (WaitForSingleObject(process,0)==WAIT_OBJECT_0) return;
    RemoteModule remote=FindModule(pid,dll.wstring(),true);
    if (!remote.base) {
        if (WaitForSingleObject(process,0)==WAIT_OBJECT_0) return;
        throw std::runtime_error("Cannot locate the pinned diagnostic module for verified stop.");
    }
    HMODULE local=LoadLibraryExW(dll.c_str(),nullptr,DONT_RESOLVE_DLL_REFERENCES);
    if (!local) WinFail("LoadLibraryExW export mapping");
    auto address=GetProcAddress(local,"ForeverTraceStop");
    uintptr_t rva=address?reinterpret_cast<uintptr_t>(address)-reinterpret_cast<uintptr_t>(local):0;
    FreeLibrary(local);
    if (!address || !rva || rva>=remote.size) throw std::runtime_error("Diagnostic stop export is missing or outside target DLL.");
    Handle thread(CreateRemoteThread(process,nullptr,0,reinterpret_cast<LPTHREAD_START_ROUTINE>(remote.base+rva),nullptr,0,nullptr));
    if (!thread.h) WinFail("CreateRemoteThread diagnostic stop");
    if (WaitForSingleObject(thread,15000)!=WAIT_OBJECT_0) throw std::runtime_error("Diagnostic stop timed out; DLL also has a 120-second auto-stop.");
    DWORD state=0;
    if (!GetExitCodeThread(thread,&state)) WinFail("GetExitCodeThread diagnostic stop");
    if (state!=3) throw std::runtime_error("Diagnostic stop did not confirm stopped state, state="+std::to_string(state));
}
void Ready(const fs::path& file,HANDLE process) {
    auto until=GetTickCount64()+15000;
    while (GetTickCount64()<until) {
        std::string text=ReadText(file);
        if (text.find("TRACE_FAILED")!=std::string::npos) throw std::runtime_error("Diagnostic DLL reported hook setup failure. See socket log.");
        if (text.find("TRACE_READY")!=std::string::npos) return;
        if (WaitForSingleObject(process,0)==WAIT_OBJECT_0) throw std::runtime_error("Target exited before diagnostic became ready.");
        Sleep(100);
    }
    throw std::runtime_error("Diagnostic initialization timed out; no TRACE_READY marker.");
}
std::wstring PsLiteral(const std::wstring& text) {
    std::wstring out=L"'";for(wchar_t c:text){out+=c;if(c==L'\'')out+=c;}return out+L"'";
}
void Zip(const fs::path& folder,const fs::path& socketLog) {
    fs::path script=folder/L"create-zip.ps1";
    std::wstring ps=L"$ErrorActionPreference='Stop'\r\nCompress-Archive -LiteralPath @("+PsLiteral((folder/L"markers.txt").wstring());
    if (fs::exists(socketLog)) ps+=L","+PsLiteral(socketLog.wstring());
    ps+=L") -DestinationPath "+PsLiteral(folder.wstring()+L".zip")+L" -ErrorAction Stop\r\n";
    std::ofstream out(script,std::ios::binary);const BYTE bom[]={0xFF,0xFE};out.write(reinterpret_cast<const char*>(bom),2);out.write(reinterpret_cast<const char*>(ps.data()),static_cast<std::streamsize>(ps.size()*sizeof(wchar_t)));out.close();
    wchar_t windows[32768]{};if (!GetWindowsDirectoryW(windows,32768)) WinFail("GetWindowsDirectoryW");
    fs::path powershell=fs::path(windows)/L"System32/WindowsPowerShell/v1.0/powershell.exe";
    std::wstring command=Quote(powershell.wstring())+L" -NoProfile -ExecutionPolicy Bypass -File "+Quote(script.wstring());
    STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
    if (!CreateProcessW(powershell.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)) WinFail("CreateProcessW ZIP helper");
    Handle proc(pi.hProcess),thread(pi.hThread);
    if(WaitForSingleObject(proc,30000)!=WAIT_OBJECT_0)throw std::runtime_error("ZIP export did not finish within 30 seconds; files remain in output folder.");
    DWORD code=1;if(!GetExitCodeProcess(proc,&code)||code!=0)throw std::runtime_error("ZIP export failed; files remain in output folder.");
    if(!fs::exists(folder.wstring()+L".zip")||fs::file_size(folder.wstring()+L".zip")>32*1024*1024)throw std::runtime_error("ZIP missing or larger than upload limit.");
}
int SocketTest(const std::wstring& gateName,const std::wstring& doneName,const std::wstring& finishName) {
    Handle gate(OpenEventW(SYNCHRONIZE,FALSE,gateName.c_str()));
    Handle done(OpenEventW(EVENT_MODIFY_STATE,FALSE,doneName.c_str()));
    Handle finish(OpenEventW(SYNCHRONIZE,FALSE,finishName.c_str()));
    if(!gate.h||!done.h||!finish.h||WaitForSingleObject(gate,30000)!=WAIT_OBJECT_0)return 20;
    WSADATA w{};bool initialized=WSAStartup(MAKEWORD(2,2),&w)==0;
    int result=initialized?0:21;SOCKET listener=INVALID_SOCKET,client=INVALID_SOCKET,accepted=INVALID_SOCKET,refused=INVALID_SOCKET,mismatch=INVALID_SOCKET;
    do {
        if(!initialized)break;
        listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(listener==INVALID_SOCKET){result=23;break;}
        sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);a.sin_port=0;
        if(bind(listener,reinterpret_cast<sockaddr*>(&a),sizeof(a))||listen(listener,1)){result=24;break;}
        int length=sizeof(a);if(getsockname(listener,reinterpret_cast<sockaddr*>(&a),&length)){result=25;break;}
        client=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(connect(client,reinterpret_cast<sockaddr*>(&a),sizeof(a))){result=26;break;}
        accepted=accept(listener,nullptr,nullptr);if(accepted==INVALID_SOCKET){result=27;break;}
        closesocket(accepted);accepted=INVALID_SOCKET;closesocket(client);client=INVALID_SOCKET;closesocket(listener);listener=INVALID_SOCKET;
        refused=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        if(connect(refused,reinterpret_cast<sockaddr*>(&a),sizeof(a))!=SOCKET_ERROR||WSAGetLastError()!=WSAECONNREFUSED){result=28;break;}
        if(closesocket(INVALID_SOCKET)!=SOCKET_ERROR||WSAGetLastError()!=WSAENOTSOCK){result=29;break;}
        mismatch=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);sockaddr_in6 v6{};v6.sin6_family=AF_INET6;v6.sin6_addr=in6addr_loopback;v6.sin6_port=a.sin_port;
        int ret=connect(mismatch,reinterpret_cast<sockaddr*>(&v6),sizeof(v6));
        if(ret==0){result=30;break;}
    }while(false);
    for(SOCKET s:{accepted,client,listener,refused,mismatch})if(s!=INVALID_SOCKET)closesocket(s);
    if(initialized)WSACleanup();
    // Stay alive until the controller has disabled hooks and checked restored bytes.
    if(!SetEvent(done))return 32;
    if(WaitForSingleObject(finish,30000)!=WAIT_OBJECT_0)return 33;
    if(result)return result;
    if(WSAStartup(MAKEWORD(2,2),&w)!=0)return 34;
    SOCKET after=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    bool okay=after!=INVALID_SOCKET;
    if(after!=INVALID_SOCKET)okay=closesocket(after)==0&&okay;
    okay=closesocket(INVALID_SOCKET)==SOCKET_ERROR&&WSAGetLastError()==WSAENOTSOCK&&okay;
    WSACleanup();return okay?0:35;
}
void VerifyRestored(const std::string& text) {
    if(text.find("TRACE_STOPPED disableStatus=0")==std::string::npos)
        throw std::runtime_error("Self-test did not observe successful live hook disabling.");
    std::map<std::string,std::string> before,restored;
    std::istringstream input(text);std::string line;
    while(std::getline(input,line)){
        auto get=[&](const std::string& field){auto start=line.find(field);if(start==std::string::npos)return std::string();start+=field.size();auto end=line.find_first_of(" \r\n",start);return line.substr(start,end-start);};
        if(line.find("HOOK_AUDIT phase=before ")!=std::string::npos)before[get("name=")]=get("bytes=");
        if(line.find("HOOK_AUDIT phase=restored ")!=std::string::npos)restored[get("name=")]=get("bytes=");
    }
    if(before.size()<10||restored.size()!=before.size())throw std::runtime_error("Self-test hook restoration audit is incomplete.");
    for(const auto& entry:before)if(entry.second.empty()||entry.second=="unreadable"||restored[entry.first]!=entry.second)
        throw std::runtime_error("Self-test original API bytes were not restored: "+entry.first);
}
int wmain(int argc,wchar_t** argv) {
    if(argc==5&&std::wstring(argv[1])==L"--socket-test")return SocketTest(argv[2],argv[3],argv[4]);
    bool self=argc>=2&&std::wstring(argv[1])==L"--self-test";
    fs::path root;
    fs::path folder;fs::path dll;fs::path log;DWORD targetPid=0;Handle process;Handle childThread;Handle gate;Handle doneGate;Handle finishGate;
    bool injected=false;int result=0;fs::path targetImage;std::string originalHash;
    try {
        root=self&&argc==3?fs::path(argv[2]):(argc==3&&std::wstring(argv[1])==L"--output-root"?fs::path(argv[2]):Desktop());
        SID_IDENTIFIER_AUTHORITY authority=SECURITY_NT_AUTHORITY; PSID admins=nullptr; BOOL admin=FALSE;
        if(!AllocateAndInitializeSid(&authority,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&admins))WinFail("AllocateAndInitializeSid");
        BOOL membership=CheckTokenMembership(nullptr,admins,&admin);FreeSid(admins);if(!membership)WinFail("CheckTokenMembership");
        if(!admin){
            if(self)throw std::runtime_error("Self-test requires an elevated helper.");
            fs::path exe=ModulePath();std::wstring args=L"--output-root "+Quote(root.wstring());
            SHELLEXECUTEINFOW run{};run.cbSize=sizeof(run);run.lpVerb=L"runas";run.lpFile=exe.c_str();run.lpParameters=args.c_str();run.nShow=SW_SHOWNORMAL;
            if(!ShellExecuteExW(&run))WinFail("Elevating diagnostic helper");
            return 0;
        }
        if(!self&&!WowProcesses().empty())throw std::runtime_error("Bitte WoW zuerst normal schliessen; den normalen Forever Launcher offen lassen.");
        folder=RunFolder(root);dll=folder/L"ForeverSocketTrace.dll";
        fs::copy_file(ModulePath().parent_path()/L"ForeverSocketTrace.dll",dll,fs::copy_options::none);
        Mark(folder,std::string("collector_pid=")+std::to_string(GetCurrentProcessId())+" SelfTest="+(self?"True":"False"));
        if(self){
            std::wstring name=L"Local\\ForeverSocketTest-"+Unique();gate.h=CreateEventW(nullptr,TRUE,FALSE,name.c_str());if(!gate.h)WinFail("CreateEventW");
            std::wstring doneName=name+L"-Done",finishName=name+L"-Finish";
            doneGate.h=CreateEventW(nullptr,TRUE,FALSE,doneName.c_str());finishGate.h=CreateEventW(nullptr,TRUE,FALSE,finishName.c_str());
            if(!doneGate.h||!finishGate.h)WinFail("CreateEventW self-test phases");
            fs::path exe=ModulePath();std::wstring command=Quote(exe.wstring())+L" --socket-test "+Quote(name)+L" "+Quote(doneName)+L" "+Quote(finishName);
            STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
            if(!CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi))WinFail("CreateProcessW self-test");
            process.h=pi.hProcess;childThread.h=pi.hThread;targetPid=pi.dwProcessId;
            if(ImagePath(process)!=exe)throw std::runtime_error("Self-test child identity mismatch.");
        }else{
            std::wcout<<L"JETZT im normalen Forever Launcher auf Play klicken.\nDieses Fenster offen lassen.\n"<<std::flush;
            ULONGLONG deadline=GetTickCount64()+90000;
            while(GetTickCount64()<deadline){auto ids=WowProcesses();if(ids.size()>1)throw std::runtime_error("Mehrere WowB-Prozesse; bitte schliessen und neu versuchen.");if(ids.size()==1){targetPid=ids[0];break;}Sleep(100);}
            if(!targetPid)throw std::runtime_error("Kein neuer WowB-Prozess innerhalb von 90 Sekunden.");
            process.h=OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ|SYNCHRONIZE,FALSE,targetPid);
            if(!process.h)WinFail("OpenProcess WowB");ValidateWow(process);
        }
        log=folder/(L"socket-"+std::to_wstring(targetPid)+L".log");Mark(folder,"target_pid="+std::to_string(targetPid));
        targetImage=ImagePath(process);originalHash=FileSha256(targetImage);Mark(folder,"Original target-file SHA256="+originalHash);
        Inject(process,targetPid,dll);injected=true;Ready(log,process);Mark(folder,"TRACE_READY confirmed");
        if(self){
            if(!SetEvent(gate))WinFail("SetEvent self-test");
            HANDLE phases[]={doneGate.h,process.h};
            DWORD wait=WaitForMultipleObjects(2,phases,FALSE,20000);
            if(wait!=WAIT_OBJECT_0)throw std::runtime_error("Self-test child did not reach live-stop phase, wait="+std::to_string(wait));
            std::string text=ReadText(log);
            for(const char* marker:{"TRACE_READY","connect","closesocket","10061","10038"})if(text.find(marker)==std::string::npos)throw std::runtime_error(std::string("Self-test missing native trace evidence: ")+marker);
            Stop(process,targetPid,dll);
            VerifyRestored(ReadText(log));
            auto stoppedSize=fs::file_size(log);
            if(!SetEvent(finishGate))WinFail("SetEvent self-test finish");
            if(WaitForSingleObject(process,10000)!=WAIT_OBJECT_0)throw std::runtime_error("Self-test child did not finish after live stop.");
            DWORD code=1;if(!GetExitCodeProcess(process,&code)||code!=0)throw std::runtime_error("Self-test socket child failed, exit="+std::to_string(code));
            if(fs::file_size(log)!=stoppedSize)throw std::runtime_error("Self-test trace continued after live hook stop.");
            Mark(folder,"SELFTEST PASS: real socket success/refusal and error preservation, live stop/restored API bytes, and post-stop socket calls verified");
        }else{
            std::wcout<<L"Diagnose aktiv. Auf Disconnected warten; Aufzeichnung endet nach 60 Sekunden.\n"<<std::flush;
            auto deadline=GetTickCount64()+60000;while(GetTickCount64()<deadline&&WaitForSingleObject(process,250)==WAIT_TIMEOUT){}
        }
        Stop(process,targetPid,dll);
        auto afterHash=FileSha256(targetImage);Mark(folder,"After target-file SHA256="+afterHash);
        if(afterHash!=originalHash)throw std::runtime_error("Target file changed during recording; collector never writes this file.");
        Mark(folder,"Stop requested; target file SHA256 unchanged; diagnostic DLL remains mapped until process exits");
        Zip(folder,log);std::wcout<<L"ZIP erstellt: "<<folder.wstring()<<L".zip\n"<<std::flush;
    }catch(const std::exception& e){
        result=1;std::cerr<<"DIAGNOSEFEHLER: "<<e.what()<<"\n";
        if(injected&&process.h){try{Stop(process,targetPid,dll);}catch(const std::exception& stop){std::cerr<<"Stop: "<<stop.what()<<"\n";}}
        if(self){if(gate.h)SetEvent(gate);if(finishGate.h)SetEvent(finishGate);if(process.h)WaitForSingleObject(process,5000);}
        if(!folder.empty()){try{Mark(folder,std::string("FAILED: ")+e.what());if(!log.empty())Zip(folder,log);}catch(...){}std::wcout<<L"Dateien: "<<folder<<L"\n";}
        if(self)std::cerr<<"::error title=Native API diagnostic self-test failed::"<<e.what()<<"\n";
    }
    if(!self){std::wcout<<L"Enter zum Schliessen.\n"<<std::flush;std::wstring line;std::getline(std::wcin,line);}return result;
}
