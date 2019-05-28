
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tchar.h>     // Must be included before strsafe.h
#include <strsafe.h>
#include <windows.h>

#undef stdout

#define assert(v)

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

#define BYTE(b, i) (((i) & (0xFF << (8*(b)))) >> (8*(b)))

#define INT_TO_BYTE(i) \
        BYTE(0, i)

#define INT_TO_2BYTES(i) \
        BYTE(0, i), \
        BYTE(1, i)

#define INT_TO_4BYTES(i) \
        BYTE(0, i), \
        BYTE(1, i), \
        BYTE(2, i), \
        BYTE(3, i)

#define INT_TO_8BYTES(i) \
        BYTE(0, i), \
        BYTE(1, i), \
        BYTE(2, i), \
        BYTE(3, i), \
        BYTE(4, i), \
        BYTE(5, i), \
        BYTE(6, i), \
        BYTE(7, i)

int imm_bits(int32_t imm) {
        if (0x80 > imm && imm > -0x80) {
                return 8;
        } else {
                return 32;
        }
}

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

void *jmp(void *buf, int32_t target) {
        int bits = imm_bits(target);
        switch (bits) {
        case 8:
                return emit(buf, 2, 0xEB, INT_TO_BYTE(target - 2));
        case 32:
                return emit(buf, 5, 0xE9, INT_TO_4BYTES(target - 5));
        }
}

#define GENERATE_REL_JUMP_FN(mnemonic, code) \
void *mnemonic(void *buf, int32_t target) { \
        int bits = imm_bits(target); \
        switch (bits) { \
        case 8: \
                return emit(buf, 2, code, INT_TO_BYTE(target - 2)); \
        case 32: \
                return emit(buf, 6, 0x0F, code + 0x10, \
                                INT_TO_4BYTES(target - 6)); \
        } \
}

GENERATE_REL_JUMP_FN(jo , 0x70); //             OF=1
GENERATE_REL_JUMP_FN(jno, 0x71); //             OF=0
GENERATE_REL_JUMP_FN(jb , 0x72); // jnae jc     CF=1
GENERATE_REL_JUMP_FN(jnb, 0x73); // jna  jnc    CF=0
GENERATE_REL_JUMP_FN(je , 0x74); // jz          ZF=1
GENERATE_REL_JUMP_FN(jne, 0x75); // jnz         ZF=0
GENERATE_REL_JUMP_FN(jna, 0x76); // jbe         CF=1 OR ZF=1
GENERATE_REL_JUMP_FN(ja , 0x77); // jnbe        CF=0 AND ZF=0
GENERATE_REL_JUMP_FN(js , 0x78); //             SF=1
GENERATE_REL_JUMP_FN(jns, 0x79); //             SF=0
GENERATE_REL_JUMP_FN(jp , 0x7A); // jpe         PF=1
GENERATE_REL_JUMP_FN(jnp, 0x7B); // jpo         PF=0
GENERATE_REL_JUMP_FN(jl , 0x7C); // jnge        SF!=OF
GENERATE_REL_JUMP_FN(jnl, 0x7D); // jge         SF==OF
GENERATE_REL_JUMP_FN(jng, 0x7E); // jle         ZF=1 OR SF!=OF
GENERATE_REL_JUMP_FN(jg , 0x7F); // jnle        ZF=0 AND SF==OF

uint8_t mod_rm(int mod, int v1, int v2) {
        assert(mod >= 0 && mod < 4); // only 0-3 are valid values for mod
        assert(v1 >= 0 && v1 < 8);   // only 0-7 are valid for v1
        assert(v2 >= 0 && v2 < 8);   // only 0-7 are valid for v2

        return (mod << 6) + (v1 << 3) + v2;
}

void *add_r(void *buf, int dst, int src) {
        return emit(buf, 3, REX_W, 0x01, mod_rm(3, dst, src));
}

void *test_r(void *buf, int dst, int src) {
        return emit(buf, 3, REX_W, 0x85, mod_rm(3, dst, src));
}

void *test_imm(void *buf, int r, int32_t imm) {
        if (r == RAX) {
                return emit(buf, 6, REX_W, 0xA9, INT_TO_4BYTES(imm));
        } else {
                return emit(buf, 7, REX_W, 0xF7,
                                mod_rm(3, r, 0), INT_TO_4BYTES(imm));
        }
}

void *cmp_r(void *buf, int dst, int src) {
        return emit(buf, 3, REX_W, 0x39, mod_rm(3, dst, src));
}

void *cmp_imm(void *buf, int r, int32_t imm) {
        int bits = imm_bits(imm);

        switch (bits) {
        case 8:
                return emit(buf, 4, REX_W, 0x83, mod_rm(0x03, 7, r),
                                INT_TO_BYTE(imm));
        case 32:
                return emit(buf, 7, REX_W, 0x81, mod_rm(0x03, 7, r),
                                INT_TO_4BYTES(imm));
        }
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

        uint8_t *executable =
                VirtualAlloc(NULL, EX_BUF_LEN, MEM_COMMIT, PAGE_READWRITE);
        if (executable == NULL) {
                DisplayError(L"VirtualAlloc");
                return 1;
        }

        uint8_t *p = executable;

        p = mov_imm(p, RAX, 1);
        p = mov_imm(p, RBX, 1);

        uint8_t *loop = p;
        p = add_r(p, RBX, RAX);
        p = add_r(p, RAX, RBX);

        p = cmp_imm(p, RAX, 1000);
        p = jng(p, (int32_t)(loop-p));

        p = ret(p);

        printf("Running:\n");
        for (int i=0; i<p-executable; i++) {
                printf("%02hhx ", executable[i]);
        }
        printf("\n");

        DWORD ignore;
        int res = VirtualProtect(executable, EX_BUF_LEN,
                        PAGE_EXECUTE_READ, &ignore);
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

