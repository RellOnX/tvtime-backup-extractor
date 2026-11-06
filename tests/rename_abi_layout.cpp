#include <windows.h>
#include <winternl.h>
#include <cstddef>
#include <cstdio>

// Native mirror from the documented FILE_RENAME_INFORMATION declaration.
// SDK FILE_RENAME_INFO below is independently supplied by the installed SDK.
struct NativeRenameMirror {
    union { BOOLEAN ReplaceIfExists; ULONG Flags; };
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
};

int main() {
    std::printf(
        "{\"pointer\":%zu,\"wchar\":%zu,\"boolean\":%zu,\"ulong\":%zu,"
        "\"io_size\":%zu,\"io_information\":%zu,"
        "\"win32\":{\"size\":%zu,\"root\":%zu,\"length\":%zu,\"name\":%zu},"
        "\"native_mirror\":{\"size\":%zu,\"root\":%zu,\"length\":%zu,\"name\":%zu}}\n",
        sizeof(HANDLE), sizeof(WCHAR), sizeof(BOOLEAN), sizeof(ULONG),
        sizeof(IO_STATUS_BLOCK), offsetof(IO_STATUS_BLOCK, Information),
        sizeof(FILE_RENAME_INFO), offsetof(FILE_RENAME_INFO, RootDirectory),
        offsetof(FILE_RENAME_INFO, FileNameLength), offsetof(FILE_RENAME_INFO, FileName),
        sizeof(NativeRenameMirror), offsetof(NativeRenameMirror, RootDirectory),
        offsetof(NativeRenameMirror, FileNameLength), offsetof(NativeRenameMirror, FileName));
}
