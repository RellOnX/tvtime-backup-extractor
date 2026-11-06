from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tvtime_extractor import extract, safety
from tvtime_extractor.errors import SourceChangedError, UnsafePathError


@contextmanager
def active_synthetic_output(path: Path):
    state = SimpleNamespace(visible_root=path)
    token = safety._WINDOWS_BOUND_OUTPUT_STATE.set(state)
    try:
        yield state
    finally:
        safety._WINDOWS_BOUND_OUTPUT_STATE.reset(token)


class BorrowedOutputBindingTests(unittest.TestCase):
    def test_borrows_live_exact_handle_and_revalidates_without_closing_it(self) -> None:
        path = Path("synthetic-output").absolute()
        binding = (path, 71, (17, 23))
        with (
            active_synthetic_output(path),
            mock.patch.object(
                safety, "_windows_bound_directory_binding", return_value=binding
            ) as check,
            mock.patch.object(safety, "_windows_pinned_absolute_directory_handle") as reopen,
            mock.patch.object(safety, "_windows_close_handle") as close,
        ):
            with safety._windows_borrow_or_pin_directory_handle(path) as handle:
                self.assertEqual(handle, 71)
            self.assertEqual(check.call_count, 2)
            reopen.assert_not_called()
            close.assert_not_called()

    def test_changed_or_removed_binding_refuses_without_fallback(self) -> None:
        path = Path("synthetic-output").absolute()
        binding = (path, 71, (17, 23))
        for after in (None, (path, 72, (17, 23)), (path, 71, (17, 24))):
            with (
                self.subTest(after=after),
                active_synthetic_output(path),
                mock.patch.object(
                    safety, "_windows_bound_directory_binding", side_effect=[binding, after]
                ),
                mock.patch.object(safety, "_windows_pinned_absolute_directory_handle") as reopen,
                mock.patch.object(safety, "_windows_close_handle") as close,
            ):
                with (
                    self.assertRaises(UnsafePathError),
                    safety._windows_borrow_or_pin_directory_handle(path),
                ):
                    pass
                reopen.assert_not_called()
                close.assert_not_called()

    def test_missing_parent_inside_active_output_refuses_before_reopen(self) -> None:
        root = Path("synthetic-output").absolute()
        with (
            active_synthetic_output(root),
            mock.patch.object(safety, "_windows_bound_directory_binding", return_value=None),
            mock.patch.object(safety, "_windows_pinned_absolute_directory_handle") as reopen,
            self.assertRaises(UnsafePathError),
            safety._windows_borrow_or_pin_directory_handle(
                root / "unretained", require_bound_within_output=True
            ),
        ):
            pass
        reopen.assert_not_called()

    def test_unbound_parent_still_uses_owned_absolute_pin(self) -> None:
        path = Path("synthetic-unbound").absolute()
        with (
            mock.patch.object(safety, "_windows_bound_directory_binding", return_value=None),
            mock.patch.object(safety, "_windows_pinned_absolute_directory_handle") as pin,
        ):
            pin.return_value.__enter__.return_value = 71
            with safety._windows_borrow_or_pin_directory_handle(path) as handle:
                self.assertEqual(handle, 71)
        pin.assert_called_once_with(path)
        pin.return_value.__exit__.assert_called_once()

    def test_caller_failure_does_not_close_borrowed_handle(self) -> None:
        path = Path("synthetic-output").absolute()
        with (
            active_synthetic_output(path),
            mock.patch.object(
                safety, "_windows_bound_directory_binding", return_value=(path, 71, (17, 23))
            ),
            mock.patch.object(safety, "_windows_close_handle") as close,
            self.assertRaisesRegex(RuntimeError, "synthetic caller failure"),
            safety._windows_borrow_or_pin_directory_handle(path),
        ):
            raise RuntimeError("synthetic caller failure")
        close.assert_not_called()

    def test_changed_output_context_refuses_even_with_same_numeric_binding(self) -> None:
        path = Path("synthetic-output").absolute()
        changed_token = None
        with (
            active_synthetic_output(path),
            mock.patch.object(
                safety, "_windows_bound_directory_binding", return_value=(path, 71, (17, 23))
            ),
        ):
            try:
                with (
                    self.assertRaises(UnsafePathError),
                    safety._windows_borrow_or_pin_directory_handle(path),
                ):
                    changed_token = safety._WINDOWS_BOUND_OUTPUT_STATE.set(
                        SimpleNamespace(visible_root=path)
                    )
            finally:
                if changed_token is not None:
                    safety._WINDOWS_BOUND_OUTPUT_STATE.reset(changed_token)


class WindowsEncryptedCopyRoutingTests(unittest.TestCase):
    def test_lexical_parent_traversal_refuses_before_binding_lookup(self) -> None:
        windows_os = mock.Mock(wraps=os)
        windows_os.name = "nt"
        with (
            mock.patch.object(extract, "os", windows_os),
            mock.patch.object(extract, "_windows_borrow_or_pin_directory_handle") as borrow,
            self.assertRaises(UnsafePathError),
        ):
            extract._source_payload_state(Path("synthetic-output") / ".." / "encrypted.bin")
        borrow.assert_not_called()

    def test_private_copy_uses_pinned_native_reader_without_mixed_stat_apis(self) -> None:
        payload = b"synthetic encrypted bytes"
        native = safety._WindowsRegularFileInformation(
            identity=(17, 23),
            byte_size=len(payload),
            last_write_time=116_444_736_000_000_000 + 123_456,
        )
        # Simulate the Windows route without changing pathlib's host-platform selection.
        windows_os = mock.Mock(wraps=os)
        windows_os.name = "nt"
        windows_os.read.side_effect = [payload, b""]
        windows_os.fstat.side_effect = AssertionError("Mixed stat API must not be used")

        @contextmanager
        def pinned_file(_parent: int, _parts: tuple[str, ...]):
            yield 91, native

        path = Path("synthetic-private-copy") / "encrypted.bin"
        with (
            mock.patch.object(extract, "os", windows_os),
            mock.patch.object(
                Path, "lstat", side_effect=AssertionError("No lstat/fstat comparison")
            ),
            mock.patch.object(
                extract, "_same_source_metadata", side_effect=AssertionError("No mixed ctime")
            ),
            mock.patch.object(extract, "_windows_borrow_or_pin_directory_handle") as parent_pin,
            mock.patch.object(
                extract, "_windows_locked_relative_regular_file_descriptor", side_effect=pinned_file
            ) as file_pin,
        ):
            parent_pin.return_value.__enter__.return_value = 71
            result = extract._source_payload_state(path)
        parent_pin.assert_called_once_with(path.absolute().parent, require_bound_within_output=True)
        file_pin.assert_called_once_with(71, ("encrypted.bin",))
        self.assertEqual((result.device, result.inode), native.identity)
        self.assertEqual(result.size, len(payload))
        self.assertEqual(result.sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(result.modified_ns, 12_345_600)
        self.assertEqual(result.changed_ns, result.modified_ns)

    def test_bound_source_route_remains_relative_and_unchanged(self) -> None:
        windows_os = mock.Mock(wraps=os)
        windows_os.name = "nt"
        with (
            mock.patch.object(extract, "os", windows_os),
            mock.patch.object(extract, "_windows_borrow_or_pin_directory_handle") as parent_pin,
            mock.patch.object(
                extract, "_windows_source_payload", return_value=("synthetic-result", None)
            ) as reader,
        ):
            result = extract._source_payload_state(Path("encrypted.bin"), source_root_descriptor=71)
        self.assertEqual(result, "synthetic-result")
        parent_pin.assert_not_called()
        reader.assert_called_once_with(
            Path("encrypted.bin"), source_root_handle=71, snapshot_destination=None
        )

    def test_unsafe_ancestor_stops_before_file_read(self) -> None:
        windows_os = mock.Mock(wraps=os)
        windows_os.name = "nt"
        with (
            mock.patch.object(extract, "os", windows_os),
            mock.patch.object(
                extract,
                "_windows_borrow_or_pin_directory_handle",
                side_effect=UnsafePathError("synthetic rejected ancestor"),
            ),
            mock.patch.object(extract, "_windows_source_payload") as reader,
            self.assertRaises(UnsafePathError),
        ):
            extract._source_payload_state(Path("synthetic-private-copy") / "encrypted.bin")
        reader.assert_not_called()

    def test_byte_count_is_still_required(self) -> None:
        windows_os = mock.Mock(wraps=os)
        windows_os.name = "nt"
        windows_os.read.side_effect = [b"synthetic", b""]

        @contextmanager
        def short_file(_parent: int, _parts: tuple[str, ...]):
            yield 91, safety._WindowsRegularFileInformation((17, 23), 999, 123)

        with (
            mock.patch.object(extract, "os", windows_os),
            mock.patch.object(extract, "_windows_borrow_or_pin_directory_handle") as parent_pin,
            mock.patch.object(
                extract, "_windows_locked_relative_regular_file_descriptor", side_effect=short_file
            ),
            self.assertRaises(SourceChangedError),
        ):
            parent_pin.return_value.__enter__.return_value = 71
            extract._source_payload_state(Path("synthetic-private-copy") / "encrypted.bin")


@unittest.skipUnless(os.name == "nt", "Requires real Windows native file bindings")
class WindowsEncryptedCopyNativeTests(unittest.TestCase):
    def test_captured_copy_can_be_verified_inside_bound_private_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "synthetic-output"
            with (
                safety.held_destination_parent(output) as (parent, identity, _visible),
                safety.anchored_bound_output_root(
                    output,
                    destination_parent_descriptor=parent,
                    expected_parent_identity=identity,
                ),
            ):
                copies = safety.secure_directory(output / "synthetic-copies")
                path = copies / "encrypted.bin"
                payload = b"synthetic encrypted capture"
                descriptor = safety.windows_create_private_capture_descriptor(path)
                try:
                    extract._write_all_to_descriptor(descriptor, payload)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                safety.secure_file(path)
                result = extract._source_payload_state(path)
                self.assertEqual(result.size, len(payload))
                self.assertEqual(result.sha256, hashlib.sha256(payload).hexdigest())

    def test_private_encrypted_copy_with_distinct_creation_and_write_times(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "encrypted.bin"
            payload = b"synthetic encrypted copy only"
            path.write_bytes(payload)
            os.utime(path, ns=(1_000_000_000_000_000_000, 1_000_000_000_000_000_000))
            result = extract._source_payload_state(path)
            self.assertEqual(result.size, len(payload))
            self.assertEqual(result.sha256, hashlib.sha256(payload).hexdigest())
            self.assertEqual(result.modified_ns, path.stat().st_mtime_ns)
            self.assertEqual(result.changed_ns, result.modified_ns)
            # Same-sized corruption must still fail the caller's content check.
            path.write_bytes(b"X" * len(payload))
            changed = extract._source_payload_state(path)
            self.assertFalse(changed.same_content(result))

    def test_native_post_read_identity_size_and_write_time_changes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "encrypted.bin"
            path.write_bytes(b"synthetic")
            real_information = safety._windows_regular_file_information
            for field in ("identity", "byte_size", "last_write_time"):
                calls = 0

                def changed_information(handle: int, field: str = field):
                    nonlocal calls
                    calls += 1
                    info = real_information(handle)
                    if calls != 2:
                        return info
                    value = (
                        (info.identity[0], info.identity[1] + 1)
                        if field == "identity"
                        else getattr(info, field) + 1
                    )
                    return replace(info, **{field: value})

                with (
                    self.subTest(field=field),
                    mock.patch.object(
                        safety, "_windows_regular_file_information", side_effect=changed_information
                    ),
                    self.assertRaises(UnsafePathError),
                ):
                    extract._source_payload_state(path)
                self.assertGreaterEqual(calls, 2)

    def test_native_file_and_ancestor_stay_pinned_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "synthetic-parent"
            parent.mkdir()
            path = parent / "encrypted.bin"
            payload = b"synthetic"
            path.write_bytes(payload)
            real_read = os.read
            checked = False

            def read_while_pinned(descriptor: int, count: int) -> bytes:
                nonlocal checked
                if not checked:
                    checked = True
                    with self.assertRaises(OSError):
                        path.write_bytes(b"tampering")
                    with self.assertRaises(OSError):
                        parent.rename(parent.with_name("synthetic-renamed"))
                return real_read(descriptor, count)

            with mock.patch.object(extract.os, "read", side_effect=read_while_pinned):
                result = extract._source_payload_state(path)
            self.assertTrue(checked)
            self.assertEqual(result.sha256, hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    unittest.main()
