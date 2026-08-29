#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>

struct PatternByte {
    BYTE value;
    bool exact;
};

struct Signature {
    const wchar_t* name;
    const char* pattern;
};

static const Signature g_signatures[] = {
    { L"MHPR - igrac / novac", "8D 88 68 01 00 00 E8 ?? ?? ?? ?? 8B F8 39 BE 4C 01 00 00 0F 84" },
    { L"MCPS - gradnja", "FF 41 08 8B 41 08 3B 41 0C 0F 93 C0 C3 CC CC CC ?? ?? ?? ?? ??" },
    { L"MRPS - istrazivanje", "8B 4E 1C 03 41 08 8B 11 3B 42 44 0F 83 ?? ?? ?? ?? 89 41 08 8B" },
    { L"MPPO - javni red", "8B 5E 34 8B F8 8B 41 7C 85 C0 ?? ?? 8B 10 89 55 FC ?? ?? C7 45" },
    { L"MAPT - akcioni poeni", "8B 41 64 8B 55 08 C7 81 34 01 00 00 FF FF FF FF 3B C2 ?? ?? 2B" },
    { L"MTAN - attrition", "89 46 44 8B 56 20 8B 52 08 8D 4E 20 8D 45 08 50 89 75 08 FF D2" },
    { L"MOAM - municija", "F3 0F 11 86 CC 20 00 00 F3 0F 10 05 ?? ?? ?? ?? 0F 2F 86 CC 20" },
    { L"MBUN - battle jedinice", "8B 8E 10 07 00 00 DB 86 10 07 00 00 85 C9 ?? ?? D8 05 ?? ?? ??" },
    { L"MOUS - stres", "01 96 F8 03 00 00 8B CE E8 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 CC" },
    { L"CHKP/CHKQ - CRC", "8B 4D 10 8B 7D 08 8B C1 8B D1 03 C6 3B FE ?? ?? 3B F8 0F 82 ??" }
};

HWND g_status = nullptr;
HWND g_output = nullptr;
HWND g_scan = nullptr;
DWORD g_pid = 0;

static std::vector<PatternByte> ParsePattern(const std::string& text) {
    std::vector<PatternByte> out;
    std::istringstream ss(text);
    std::string token;
    while (ss >> token) {
        if (token == "?" || token == "??") {
            out.push_back({0, false});
        } else {
            out.push_back({static_cast<BYTE>(std::stoul(token, nullptr, 16)), true});
        }
    }
    return out;
}

static DWORD FindAttilaProcess() {
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"Attila.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static bool IsExecutable(DWORD protect) {
    DWORD p = protect & 0xFF;
    return p == PAGE_EXECUTE ||
           p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE ||
           p == PAGE_EXECUTE_WRITECOPY;
}

static std::vector<uintptr_t> ScanPattern(HANDLE process, const std::vector<PatternByte>& pat) {
    std::vector<uintptr_t> hits;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    uintptr_t addr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    uintptr_t maxAddr = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION mbi{};
    const SIZE_T chunkSize = 1024 * 1024;

    while (addr < maxAddr) {
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi)) {
            addr += 0x1000;
            continue;
        }

        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        SIZE_T region = mbi.RegionSize;

        bool readableExec = mbi.State == MEM_COMMIT &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            IsExecutable(mbi.Protect);

        if (readableExec && region > 0 && !pat.empty()) {
            SIZE_T offset = 0;
            SIZE_T overlap = pat.size() > 1 ? pat.size() - 1 : 0;

            while (offset < region) {
                SIZE_T toRead = min(chunkSize, region - offset);
                std::vector<BYTE> buffer(toRead);
                SIZE_T got = 0;

                if (ReadProcessMemory(process,
                    reinterpret_cast<LPCVOID>(base + offset),
                    buffer.data(), toRead, &got) && got >= pat.size()) {

                    for (SIZE_T i = 0; i + pat.size() <= got; ++i) {
                        bool ok = true;
                        for (SIZE_T j = 0; j < pat.size(); ++j) {
                            if (pat[j].exact && buffer[i + j] != pat[j].value) {
                                ok = false;
                                break;
                            }
                        }
                        if (ok) hits.push_back(base + offset + i);
                    }
                }

                if (toRead <= overlap) break;
                offset += toRead - overlap;
            }
        }

        if (region == 0) break;
        addr = base + region;
    }

    std::sort(hits.begin(), hits.end());
    hits.erase(std::unique(hits.begin(), hits.end()), hits.end());
    return hits;
}

static void UpdateProcessStatus() {
    g_pid = FindAttilaProcess();
    if (g_pid) {
        std::wstringstream ss;
        ss << L"IGRA PRONADJENA - PID " << g_pid;
        SetWindowTextW(g_status, ss.str().c_str());
        EnableWindow(g_scan, TRUE);
    } else {
        SetWindowTextW(g_status, L"IGRA NIJE PRONADJENA");
        EnableWindow(g_scan, FALSE);
    }
}

static void RunScan() {
    if (!g_pid) return;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, g_pid);
    if (!process) {
        MessageBoxW(nullptr,
            L"Ne mogu da otvorim Attila.exe.\nProbaj da pokrenes trainer kao Administrator.",
            L"Greska", MB_ICONERROR);
        return;
    }

    EnableWindow(g_scan, FALSE);

    std::wstringstream output;
    output << L"Attila.exe PID: " << g_pid << L"\r\n";
    output << L"============================================================\r\n";

    for (const auto& sig : g_signatures) {
        auto pat = ParsePattern(sig.pattern);
        auto hits = ScanPattern(process, pat);

        output << L"\r\n" << sig.name << L": ";
        if (hits.empty()) {
            output << L"NIJE NADJENO";
        } else if (hits.size() == 1) {
            output << L"UNIQUE";
        } else {
            output << L"VISE REZULTATA (" << hits.size() << L")";
        }

        for (size_t i = 0; i < hits.size() && i < 10; ++i) {
            output << L"\r\n    0x"
                   << std::uppercase << std::hex << std::setw(8)
                   << std::setfill(L'0') << hits[i]
                   << std::dec;
        }
        output << L"\r\n";
        SetWindowTextW(g_output, output.str().c_str());
    }

    output << L"\r\n============================================================\r\n";
    output << L"Ako su kljucni potpisi UNIQUE, sledeci korak su ON/OFF hookovi.\r\n";
    SetWindowTextW(g_output, output.str().c_str());

    CloseHandle(process);
    EnableWindow(g_scan, TRUE);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        CreateWindowW(L"STATIC", L"ATTILA: TOTAL WAR - SRPSKI TRAINER",
            WS_CHILD | WS_VISIBLE, 20, 18, 520, 28, hwnd, nullptr, nullptr, nullptr);

        g_status = CreateWindowW(L"STATIC", L"IGRA NIJE PRONADJENA",
            WS_CHILD | WS_VISIBLE, 20, 58, 500, 24, hwnd, nullptr, nullptr, nullptr);

        g_scan = CreateWindowW(L"BUTTON", L"SKENIRAJ AOB POTPISE",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            20, 90, 220, 36, hwnd, reinterpret_cast<HMENU>(1001), nullptr, nullptr);

        g_output = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            L"Ova verzija ne zavisi od Attila.dll po imenu.\r\n"
            L"Pokreni igru, pa klikni SKENIRAJ AOB POTPISE.\r\n",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
            ES_AUTOVSCROLL | WS_VSCROLL,
            20, 145, 740, 400, hwnd, nullptr, nullptr, nullptr);

        SendMessageW(g_output, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(ANSI_FIXED_FONT)), TRUE);

        SetTimer(hwnd, 1, 1000, nullptr);
        UpdateProcessStatus();
        return 0;
    }

    case WM_TIMER:
        UpdateProcessStatus();
        return 0;

    case WM_COMMAND:
        if (LOWORD(wp) == 1001) {
            RunScan();
            return 0;
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int show) {
    const wchar_t CLASS_NAME[] = L"AttilaSerbianTrainerWindow";

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(
        0, CLASS_NAME, L"Attila Serbian Trainer - Native C++",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        nullptr, nullptr, hInst, nullptr);

    if (!hwnd) return 0;

    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
