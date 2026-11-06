from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from tvtime_extractor import windows_native as native
from tvtime_extractor.safety import _windows_close_handle, _windows_open_locked_directory


def number(value):
    return value if type(value) is int and -(2**31) <= value < 2**32 else None


def fixed_error(error: Exception) -> dict:
    kind = "unexpected_exception"
    if isinstance(error, PermissionError):
        kind = "permission_error"
    elif isinstance(error, FileNotFoundError):
        kind = "not_found"
    elif isinstance(error, OSError):
        kind = "other_os_error"
    return {
        "error_kind": kind,
        "errno": number(getattr(error, "errno", None)),
        "winerror": number(getattr(error, "winerror", None)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()
    report = {
        "schema": "synthetic-guard-numeric-report-v1",
        "guard": "write_open",
        "guard_attempts": 0,
        "rename_calls": 0,
        "blocked_operation_retried": False,
        "guard_acceptance_policy_changed": False,
        "release_gate_pass": False,
    }
    stage = "runtime_check"
    parent = None
    root = None
    source = None
    parent_handle = -1
    root_handle = -1
    descriptor = -1
    created_root = False
    created_source = False
    cleanup_errors = []
    exit_code = 1
    try:
        if (
            os.name != "nt"
            or sys.version_info[:3] != (3, 13, 12)
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_OS") != "Windows"
        ):
            raise RuntimeError("cloud_runtime_required")
        stage = "fixture_parent_create"
        parent = Path(tempfile.mkdtemp(prefix="synthetic-guard-report-"))
        root = parent / "synthetic-root"
        source = root / "synthetic-stage.partial"
        stage = "fixture_parent_open"
        parent_handle, _ = _windows_open_locked_directory(parent, allow_child_creation=True)
        native.require_private_ntfs_volume(parent_handle)
        stage = "fixture_root_create"
        root_handle = native.create_fresh_directory(parent_handle, root.name)
        created_root = True
        stage = "fixture_file_create"
        handle = native.create_relative_regular_file_path(
            root_handle, (source.name,), temporary=True
        )
        created_source = True
        descriptor = native.handle_to_file_descriptor(
            handle, flags=os.O_RDWR | getattr(os, "O_BINARY", 0)
        )
        stage = "fixture_write"
        payload = b"invented guard report only"
        if os.write(descriptor, payload) != len(payload):
            raise RuntimeError("synthetic_write_short")
        os.fsync(descriptor)
        import msvcrt

        stage = "fixture_identity_check"
        exact_handle = int(msvcrt.get_osfhandle(descriptor))
        info = native.handle_information(exact_handle)
        native.validate_private_acl(exact_handle)
        matches = [entry for entry in native.directory_entries(root_handle) if entry.name == source.name]
        if len(matches) != 1 or matches[0].identity != info.identity or info.byte_size != len(payload):
            raise RuntimeError("synthetic_identity_mismatch")
        report["fresh_fixture_identity_verified"] = True

        # One predeclared negative control. Any error ends the experiment immediately.
        # No alternate access flags, second guard or rename call exists in this program.
        stage = "guard_write_open"
        report["guard_attempts"] = 1
        try:
            source.write_bytes(b"blocked")
        except OSError as error:
            record = fixed_error(error)
            report.update(record)
            report["accepted_by_existing_winerror_policy"] = record["winerror"] in {5, 32, 33}
            report["outcome"] = "recorded_os_error_and_stopped"
            exit_code = 0  # Report captured, NOT a safety/release gate pass.
        else:
            report["outcome"] = "guard_failed_unexpected_success"
    except Exception as error:
        report.update(outcome="stopped_before_guard", stage=stage, **fixed_error(error))
    finally:
        # Release only this fixture's owned handles, once each. No permission changes,
        # recursive delete, access workaround or retry is used during cleanup.
        for close_stage, value, close in (
            ("close_fixture_file", descriptor, os.close),
            ("close_fixture_root", root_handle, native.close_handle),
            ("close_fixture_parent", parent_handle, _windows_close_handle),
        ):
            if value >= 0:
                try:
                    close(value)
                except Exception as error:
                    cleanup_errors.append({"stage": close_stage, **fixed_error(error)})
        if not cleanup_errors:
            try:
                if created_source:
                    source.unlink()
                if created_root:
                    root.rmdir()
                if parent is not None:
                    parent.rmdir()
            except Exception as error:
                cleanup_errors.append({"stage": "remove_owned_fixture", **fixed_error(error)})
        report["cleanup_completed"] = not cleanup_errors
        if cleanup_errors:
            report["cleanup_errors"] = cleanup_errors
            exit_code = 1
    args.summary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
