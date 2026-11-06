from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path

from tvtime_extractor import windows_native as native
from tvtime_extractor.safety import _windows_close_handle, _windows_open_locked_directory


class ProbeStopped(Exception):
    pass


class NativeRenameInfo(ctypes.Structure):
    _fields_ = [
        ("ReplaceIfExists", wintypes.BOOLEAN),
        ("RootDirectory", wintypes.HANDLE),
        ("FileNameLength", wintypes.ULONG),
        ("FileName", wintypes.WCHAR * 1),
    ]


CASES = (
    ("A-win32-existing-size", "win32", True, False),
    ("B-win32-full-size", "win32", True, True),
    ("C-native-relative-parent", "native", True, True),
    ("D-native-same-parent", "native", False, True),
)
PAYLOAD = b"invented rename probe bytes only"
TARGET = b"invented preexisting target bytes"
LEAF = "synthetic-final.bin"


def require(condition: bool, category: str) -> None:
    if not condition:
        raise ProbeStopped(category)


def layout(structure) -> dict[str, int]:
    return {
        "size": ctypes.sizeof(structure),
        "root": structure.RootDirectory.offset,
        "length": structure.FileNameLength.offset,
        "name": structure.FileName.offset,
    }


@contextmanager
def fixture(collision: bool = False):
    parent_handle = -1
    root_handle = -1
    descriptor = -1
    previous_cwd = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="synthetic-rename-probe-") as temporary:
        parent = Path(temporary)
        root = parent / "synthetic-root"
        cwd = parent / "synthetic-cwd"
        cwd.mkdir()
        try:
            parent_handle, _ = _windows_open_locked_directory(parent, allow_child_creation=True)
            native.require_private_ntfs_volume(parent_handle)
            root_handle = native.create_fresh_directory(parent_handle, root.name)
            source = native.create_relative_regular_file_path(
                root_handle, ("synthetic-stage.partial",), temporary=True
            )
            descriptor = native.handle_to_file_descriptor(
                source, flags=os.O_RDWR | getattr(os, "O_BINARY", 0)
            )
            require(os.write(descriptor, PAYLOAD) == len(PAYLOAD), "synthetic_write_short")
            os.fsync(descriptor)
            if collision:
                target = native.create_relative_regular_file_path(root_handle, (LEAF,))
                target_fd = native.handle_to_file_descriptor(
                    target, flags=os.O_RDWR | getattr(os, "O_BINARY", 0)
                )
                try:
                    require(os.write(target_fd, TARGET) == len(TARGET), "synthetic_target_short")
                    os.fsync(target_fd)
                finally:
                    os.close(target_fd)
            os.chdir(cwd)
            yield root, cwd, root_handle, descriptor
        finally:
            os.chdir(previous_cwd)
            if descriptor >= 0:
                os.close(descriptor)
            if root_handle >= 0:
                native.close_handle(root_handle)
            if parent_handle >= 0:
                _windows_close_handle(parent_handle)


def source_unchanged(descriptor: int, before) -> bool:
    import msvcrt

    handle = int(msvcrt.get_osfhandle(descriptor))
    after = native.handle_information(handle)
    os.lseek(descriptor, 0, os.SEEK_SET)
    payload = os.read(descriptor, len(PAYLOAD) + 1)
    native.validate_private_acl(handle)
    return (
        after.identity == before.identity
        and after.byte_size == before.byte_size
        and after.last_write_time == before.last_write_time
        and len(payload) == len(PAYLOAD)
        and hashlib.sha256(payload).digest() == hashlib.sha256(PAYLOAD).digest()
    )


def guard_blocked(operation) -> bool:
    try:
        operation()
    except OSError as error:
        require(getattr(error, "winerror", None) in {5, 32, 33}, "unexpected_guard_error")
        return True
    return False


def call(case, source_handle: int, parent_handle: int) -> dict:
    _identifier, api, has_root, full_size = case
    structure = native._FILE_RENAME_INFO if api == "win32" else NativeRenameInfo
    encoded = LEAF.encode("utf-16-le")
    offset = structure.FileName.offset
    size = (ctypes.sizeof(structure) if full_size else offset) + len(encoded) + 2
    buffer = ctypes.create_string_buffer(size)
    info = ctypes.cast(buffer, ctypes.POINTER(structure)).contents
    info.ReplaceIfExists = False
    info.RootDirectory = parent_handle if has_root else None
    info.FileNameLength = len(encoded)
    ctypes.memmove(ctypes.addressof(buffer) + offset, encoded, len(encoded))
    result = {
        "api": api,
        "class": 3 if api == "win32" else 10,
        "root_present": has_root,
        "allocation_bytes": size,
        "filename_bytes": len(encoded),
        "replace": False,
    }
    if api == "win32":
        function = native._dll("kernel32").SetFileInformationByHandle
        function.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        function.restype = wintypes.BOOL
        ctypes.set_last_error(0)
        ok = bool(function(wintypes.HANDLE(source_handle), 3, buffer, size))
        code = 0 if ok else int(ctypes.get_last_error())
        result.update(completed_success=ok, winerror=code)
    else:
        function = native._dll("ntdll").NtSetInformationFile
        function.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(native._IO_STATUS_BLOCK),
            wintypes.LPVOID,
            wintypes.ULONG,
            ctypes.c_int,
        ]
        function.restype = wintypes.LONG
        status_block = native._IO_STATUS_BLOCK()
        status_block.Status = 0x7FFFFFFF
        status = int(function(wintypes.HANDLE(source_handle), ctypes.byref(status_block), buffer, size, 10))
        unsigned = status & 0xFFFFFFFF
        result["ntstatus"] = f"0x{unsigned:08X}"
        result["io_status"] = f"0x{int(status_block.Status) & 0xFFFFFFFF:08X}"
        if unsigned == 0x00000103:
            result.update(completed_success=False, winerror=None, outcome_uncertain=True)
            return result
        if status == 0:
            require(int(status_block.Status) == 0, "native_completion_not_verified")
            code = 0
        else:
            convert = native._dll("ntdll").RtlNtStatusToDosError
            convert.argtypes = [wintypes.LONG]
            convert.restype = wintypes.ULONG
            code = int(convert(wintypes.LONG(status)))
        result.update(completed_success=(status == 0), winerror=code)
    return result


def run_case(case, result: dict) -> dict:
    import msvcrt

    with fixture() as (root, cwd, parent_handle, descriptor):
        handle = int(msvcrt.get_osfhandle(descriptor))
        before = native.handle_information(handle)
        require(guard_blocked(lambda: (root / "synthetic-stage.partial").write_bytes(b"blocked")), "write_guard_failed")
        require(guard_blocked(lambda: (root / "synthetic-stage.partial").unlink()), "unlink_guard_failed")
        require(guard_blocked(lambda: root.rename(root.with_name("synthetic-moved"))), "parent_guard_failed")
        result.update(call(case, handle, parent_handle))
        require(not result.get("outcome_uncertain", False), "native_pending_outcome_uncertain")
        require(result["winerror"] not in {5, 32, 33}, "rename_access_or_sharing_denial")
        require(result["winerror"] in {0, 87}, "unplanned_primary_result")
        require(source_unchanged(descriptor, before), "source_integrity_changed")
        entries = native.directory_entries(parent_handle)
        expected_name = LEAF if result["completed_success"] else "synthetic-stage.partial"
        matches = [entry for entry in entries if entry.name == expected_name]
        require(len(matches) == 1 and matches[0].identity == before.identity, "destination_binding_failed")
        require(not (cwd / LEAF).exists(), "destination_escaped_to_cwd")
        result.update(
            identity_size_write_time_hash_preserved=True,
            destination_bound_to_source_parent=True,
            no_cwd_escape=True,
            write_unlink_parent_rename_blocked=True,
        )
    if result["completed_success"]:
        with fixture(collision=True) as (root, cwd, parent_handle, descriptor):
            handle = int(msvcrt.get_osfhandle(descriptor))
            before = native.handle_information(handle)
            collision = call(case, handle, parent_handle)
            result["collision"] = collision
            require(not collision.get("outcome_uncertain", False), "collision_pending_uncertain")
            require(collision["winerror"] not in {5, 32, 33}, "collision_access_or_sharing_denial")
            require(not collision["completed_success"] and collision["winerror"] in {80, 183}, "no_replace_failed")
            require(source_unchanged(descriptor, before), "collision_source_changed")
            require((root / LEAF).read_bytes() == TARGET, "collision_target_changed")
            require(not (cwd / LEAF).exists(), "collision_cwd_escape")
            result["collision_preserved_both_files"] = True
    else:
        result["collision"] = "not_exercised_unsuccessful_contract"
    result["cleanup_completed"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk-layout", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()
    report = {"schema": "synthetic-rename-abi-probe-v1", "cases": [], "production_fallback": False}
    try:
        require(os.name == "nt", "windows_required")
        require(
            os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_OS") == "Windows",
            "cloud_runner_required",
        )
        require(tuple(__import__("sys").version_info[:3]) == (3, 13, 12), "wrong_python_runtime")
        sdk = json.loads(args.sdk_layout.read_text(encoding="utf-8-sig"))
        report["sdk_layout"] = sdk
        report["ctypes_win32"] = layout(native._FILE_RENAME_INFO)
        report["ctypes_native"] = layout(NativeRenameInfo)
        require(sdk["pointer"] == ctypes.sizeof(wintypes.HANDLE) == 8, "pointer_abi_mismatch")
        require(sdk["wchar"] == ctypes.sizeof(wintypes.WCHAR) == 2, "wchar_abi_mismatch")
        require(sdk["boolean"] == ctypes.sizeof(wintypes.BOOLEAN) == 1, "boolean_abi_mismatch")
        require(sdk["ulong"] == ctypes.sizeof(wintypes.ULONG) == 4, "ulong_abi_mismatch")
        require(sdk["win32"] == layout(native._FILE_RENAME_INFO), "win32_sdk_abi_mismatch")
        require(sdk["native_mirror"] == layout(NativeRenameInfo), "native_compiler_abi_mismatch")
        require(sdk["io_size"] == ctypes.sizeof(native._IO_STATUS_BLOCK), "io_status_size_mismatch")
        require(
            sdk["io_information"] == native._IO_STATUS_BLOCK.Information.offset,
            "io_status_information_mismatch",
        )
        report["abi_verified"] = True
        for case in CASES:
            result = {"case": case[0]}
            report["cases"].append(result)
            run_case(case, result)
        report["outcome"] = "completed_predeclared_cases"
        return_code = 0
    except Exception as error:
        report["outcome"] = "stopped"
        report["category"] = str(error) if isinstance(error, ProbeStopped) else "unexpected_exception"
        report["error_type"] = type(error).__name__
        return_code = 1
    args.summary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, separators=(",", ":")))
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
