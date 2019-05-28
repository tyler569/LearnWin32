
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tchar.h>     // Must be included before strsafe.h
#include <strsafe.h>
#include <windows.h>

#undef stdout

static void DisplayError(LPTSTR failedFunctionName);

int random_int(int max) {
        return rand() % max;
}

uint8_t *emit(uint8_t *buf, int len, ...) {
        va_list va;
        va_start(va, len);

        for (int i=0; i<len; i++) {
                buf[i] = va_arg(va, int);
        }
        va_end(va);
        return buf + len;
}

enum {
        LOCK  = 0xF0,
        REX_W = 0x48,
};

enum {
        RAX = 0,
        RCX = 1,
        RDX = 2,
        RBX = 3,
        RSP = 4,
        RBP = 5,
        RSI = 6,
        RDI = 7,
};

#define INT_TO_4BYTES(i) \
        (i & 0xFF), \
        (i & 0xFF00) >> 8, \
        (i & 0xFF0000) >> 16, \
        (i & 0xFF000000) >> 24

#define INT_TO_8BYTES(i) \
        (i & 0xFF), \
        (i & 0xFF00) >> 8, \
        (i & 0xFF0000) >> 16, \
        (i & 0xFF000000) >> 24, \
        (i & 0xFF00000000) >> 32, \
        (i & 0xFF0000000000) >> 40, \
        (i & 0xFF000000000000) >> 48, \
        (i & 0xFF00000000000000) >> 56

void *mov_imm(void *buf, int reg, uint64_t val) {
        if (val <= 0xFFFFFFFF) {
                return emit(buf, 5, 0xB8 + reg, INT_TO_4BYTES(val));
        } else {
                return emit(buf, 10, REX_W, 0xB8 + reg, INT_TO_8BYTES(val));
        }
}

void *ret(void *buf) {
        return emit(buf, 1, 0xC3);
}

#define EX_BUF_LEN 1024

int main(int argc, char **argv) {
        srand(time(NULL));
        DWORD written = 0;

        CHAR msg[] = "Hello World from Win32!\n";
        HANDLE stdout = GetStdHandle(STD_OUTPUT_HANDLE);
        // the -1 is to not print the \0
        WriteFile(stdout, msg, sizeof(msg) - 1, &written, NULL);

        CHAR buffer[256] = {0};
        INT len = sprintf_s(buffer, 256, "wrote %ld\n", written);
        WriteFile(stdout, buffer, len, NULL, NULL);

        BY_HANDLE_FILE_INFORMATION file_information = {0};
        GetFileInformationByHandle(stdout, &file_information);

        printf("stdout attributes: %lx\n", file_information.dwFileAttributes);

        printf("argument count: %d\n", argc);
        for (int i=0; i<argc; i++) {
                printf("argument %d = '%s'\n", i, argv[i]);
        }

        void *executable =
                VirtualAlloc(NULL, EX_BUF_LEN, MEM_COMMIT, PAGE_READWRITE);
        if (executable == NULL) {
                DisplayError(L"VirtualAlloc");
                return 1;
        }

        void *p = executable;

        p = mov_imm(p, RAX, 0x01);
        p = ret(p);

        DWORD ignore;
        int res = VirtualProtect(executable, EX_BUF_LEN, PAGE_EXECUTE_READ, &ignore);
        if (!res) {
                DisplayError(L"VirtualProtect");
                return 2;
        }

        res = FlushInstructionCache(GetCurrentProcess(), executable, EX_BUF_LEN);
        if (!res) {
                DisplayError(L"FlushInstructionCache");
                return 3;
        }

        uint64_t (*fn)(void) = (uint64_t(*)(void))executable;
        uint64_t x = fn();
        printf("fn returned %lld\n", x);

        res = VirtualFree(executable, 0, MEM_RELEASE);
        if (!res) {
                DisplayError(L"VirtualFree");
                return 4;
        }

        return 0;
}

#if 0
printf("This is Win32\n");

int result = MessageBox(NULL, L"Hello World", L"This is a message box",
                MB_YESNO | MB_ICONINFORMATION);

switch (result) {
        case IDYES:
                printf("YES!\n");
                break;
        case IDNO:
                printf("NO!\n");
                break;
        default:
                printf("huh?\n");
}
#endif

// from https://msdn.microsoft.com/en-us/library/windows/desktop/ms680582.aspx
static void DisplayError(LPTSTR failedFunctionName) {
        DWORD errorCode = GetLastError();
        LPVOID msgBufPtr;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
                        | FORMAT_MESSAGE_FROM_SYSTEM
                        | FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL,
                        errorCode,
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        (LPTSTR)& msgBufPtr,
                        0,
                        NULL);

        size_t size = sizeof(TCHAR) * (lstrlen((LPCTSTR)msgBufPtr)
                        + lstrlen((LPCTSTR)failedFunctionName)
                        + 40 /* Static text below */);
        LPVOID displayBufPtr = (LPVOID)LocalAlloc(LMEM_ZEROINIT, size);
        StringCchPrintf((LPTSTR)displayBufPtr,
                        LocalSize(displayBufPtr) / sizeof(TCHAR),
                        TEXT("%s failed with error %d: %s"),
                        failedFunctionName,
                        errorCode,
                        msgBufPtr);
        MessageBox(NULL, (LPCTSTR)displayBufPtr, TEXT("Error"), MB_ICONERROR);

        LocalFree(msgBufPtr);
        LocalFree(displayBufPtr);
}

volatile const LPSTR message =
"Unfortunately, there is a radio connected to my brain";

