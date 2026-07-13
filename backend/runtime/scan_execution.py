"""Thread-safe cancellation and managed subprocess execution for one scan."""
from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Sequence


_POLL_SECONDS = 0.1
_OUTPUT_TAIL_CHARS = 16_000


class SandboxCommandError(RuntimeError):
    """Base error carrying bounded command diagnostics without environment values."""

    def __init__(self, message: str, *, phase: str, timeout_seconds: float | None = None,
                 stdout: str = "", stderr: str = "") -> None:
        super().__init__(message)
        self.phase = phase
        self.timeout_seconds = timeout_seconds
        self.stdout = _tail(stdout)
        self.stderr = _tail(stderr)


class SandboxCommandCancelled(SandboxCommandError):
    """Raised after a cancelled command's whole process tree has been reaped."""


class SandboxCommandTimeout(SandboxCommandError):
    """Raised after a timed-out command's whole process tree has been reaped."""


@dataclass
class _ScanState:
    cancelled: bool = False
    db_mutation_lock: threading.RLock = field(default_factory=threading.RLock)
    processes: set[subprocess.Popen] = field(default_factory=set)
    cleanup_callbacks: dict[int, Callable[[], None]] = field(default_factory=dict)
    next_cleanup_token: int = 1


_LOCK = threading.RLock()
_SCANS: dict[str, _ScanState] = {}


def begin_scan(scan_id: str) -> None:
    """Open a scan execution scope without clearing a pre-existing cancel latch."""
    with _LOCK:
        _SCANS.setdefault(str(scan_id), _ScanState())


def is_cancelled(scan_id: str) -> bool:
    with _LOCK:
        state = _SCANS.get(str(scan_id))
        return bool(state and state.cancelled)


@contextmanager
def scan_mutation_lock(scan_id: str):
    """Serialize short, in-process DB mutations for one scan.

    This is deliberately only a single-process lifecycle lock: it must never
    cover a scan, Docker build, or network request.  Multi-worker deployments
    still rely on a fresh DB-status check inside the critical section as a
    best-effort cross-worker backstop.
    """
    with _LOCK:
        lock = _SCANS.setdefault(str(scan_id), _ScanState()).db_mutation_lock
    with lock:
        yield


def register_managed_process(scan_id: str, proc: subprocess.Popen) -> bool:
    """Register a process, or terminate it immediately if cancellation already won."""
    terminate_now = False
    with _LOCK:
        state = _SCANS.setdefault(str(scan_id), _ScanState())
        if state.cancelled:
            terminate_now = True
        else:
            state.processes.add(proc)
    if terminate_now:
        _terminate_process_tree(proc)
        _reap_process(proc)
        return False
    return True


def unregister_managed_process(scan_id: str, proc: subprocess.Popen) -> None:
    with _LOCK:
        state = _SCANS.get(str(scan_id))
        if state is not None:
            state.processes.discard(proc)


def register_cleanup_callback(scan_id: str, callback: Callable[[], None]) -> int | None:
    """Register one idempotence token, or run immediately if cancellation won."""
    run_now = False
    token = None
    with _LOCK:
        state = _SCANS.setdefault(str(scan_id), _ScanState())
        if state.cancelled:
            run_now = True
        else:
            token = state.next_cleanup_token
            state.next_cleanup_token += 1
            state.cleanup_callbacks[token] = callback
    if run_now:
        _run_cleanup_callback(callback)
    return token


def unregister_cleanup_callback(scan_id: str, token: int | None) -> None:
    if token is None:
        return
    with _LOCK:
        state = _SCANS.get(str(scan_id))
        if state is not None:
            state.cleanup_callbacks.pop(token, None)


def has_active_scan_resources(scan_id: str) -> bool:
    """Whether an in-process scan still owns cancellable processes or cleanup."""
    with _LOCK:
        state = _SCANS.get(str(scan_id))
        return bool(state and (state.processes or state.cleanup_callbacks))


def cancel_scan_resources(scan_id: str) -> int:
    """Terminate processes, then invoke each detached cleanup callback once."""
    with _LOCK:
        state = _SCANS.setdefault(str(scan_id), _ScanState())
        processes = list(state.processes)
        state.processes.clear()
        callbacks = list(state.cleanup_callbacks.values())
        state.cleanup_callbacks.clear()
    terminated = sum(1 for proc in processes if _terminate_process_tree(proc))
    cleaned = sum(1 for callback in callbacks if _run_cleanup_callback(callback))
    return terminated + cleaned


def request_cancel(scan_id: str) -> int:
    """Latch cancellation and terminate resources; repeated requests are idempotent."""
    with _LOCK:
        state = _SCANS.setdefault(str(scan_id), _ScanState())
        state.cancelled = True
    return cancel_scan_resources(scan_id)


def finish_scan(scan_id: str) -> None:
    """Close a scan scope after the caller has completed all cleanup."""
    with _LOCK:
        state = _SCANS.get(str(scan_id))
        if state is not None:
            state.cancelled = True
    cancel_scan_resources(scan_id)
    with _LOCK:
        _SCANS.pop(str(scan_id), None)


def run_managed_command(
    scan_id: str,
    cmd: Sequence[str],
    cwd: str | Path | None,
    env: Mapping[str, str] | None,
    timeout: float | None,
    phase: str,
    *,
    deadline: float | None = None,
    output_tail_chars: int = _OUTPUT_TAIL_CHARS,
) -> subprocess.CompletedProcess:
    """Run a cancellable command in its own process group against a monotonic deadline."""
    if is_cancelled(scan_id):
        raise SandboxCommandCancelled("scan cancellation requested", phase=phase)

    started = time.monotonic()
    timeout_deadline = started + max(0.0, float(timeout)) if timeout is not None else None
    absolute_deadline = min(
        value for value in (timeout_deadline, deadline) if value is not None
    ) if timeout_deadline is not None or deadline is not None else None

    popen_kwargs = {
        "cwd": str(cwd) if cwd is not None else None,
        "env": dict(env) if env is not None else None,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(list(cmd), **popen_kwargs)
    if not register_managed_process(scan_id, proc):
        raise SandboxCommandCancelled("scan cancellation requested", phase=phase)

    stdout_tail = _TailCollector(output_tail_chars)
    stderr_tail = _TailCollector(output_tail_chars)
    readers = [
        threading.Thread(target=_drain_pipe, args=(proc.stdout, stdout_tail), daemon=True),
        threading.Thread(target=_drain_pipe, args=(proc.stderr, stderr_tail), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        while True:
            if is_cancelled(scan_id):
                _stop_and_reap(proc, readers)
                raise SandboxCommandCancelled(
                    "scan cancellation requested", phase=phase,
                    stdout=stdout_tail.value(), stderr=stderr_tail.value(),
                )
            now = time.monotonic()
            if absolute_deadline is not None and now >= absolute_deadline:
                _stop_and_reap(proc, readers)
                raise SandboxCommandTimeout(
                    f"command timed out during {phase}", phase=phase,
                    timeout_seconds=timeout,
                    stdout=stdout_tail.value(), stderr=stderr_tail.value(),
                )
            wait_for = _POLL_SECONDS
            if absolute_deadline is not None:
                wait_for = max(0.001, min(wait_for, absolute_deadline - now))
            try:
                proc.wait(timeout=wait_for)
                _join_readers(readers)
                return subprocess.CompletedProcess(
                    list(cmd), proc.returncode,
                    stdout_tail.value(), stderr_tail.value(),
                )
            except subprocess.TimeoutExpired:
                continue
    finally:
        unregister_managed_process(scan_id, proc)


def _stop_and_reap(proc: subprocess.Popen, readers: list[threading.Thread]) -> None:
    _terminate_process_tree(proc)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    _join_readers(readers)


def _reap_process(proc: subprocess.Popen) -> tuple[str, str]:
    try:
        return proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        return proc.communicate()


class _TailCollector:
    def __init__(self, limit: int) -> None:
        self.limit = max(0, int(limit))
        self.chunks: deque[str] = deque()
        self.length = 0
        self.lock = threading.Lock()

    def append(self, chunk: str) -> None:
        if not chunk or self.limit == 0:
            return
        with self.lock:
            self.chunks.append(chunk)
            self.length += len(chunk)
            while self.chunks and self.length - len(self.chunks[0]) >= self.limit:
                self.length -= len(self.chunks.popleft())
            if self.length > self.limit and self.chunks:
                excess = self.length - self.limit
                self.chunks[0] = self.chunks[0][excess:]
                self.length = self.limit

    def value(self) -> str:
        with self.lock:
            return "".join(self.chunks)[-self.limit:] if self.limit else ""


def _drain_pipe(pipe, collector: _TailCollector) -> None:
    if pipe is None:
        return
    try:
        while True:
            chunk = pipe.read(4096)
            if not chunk:
                break
            collector.append(chunk)
    finally:
        pipe.close()


def _join_readers(readers: list[threading.Thread]) -> None:
    for reader in readers:
        reader.join(timeout=5)


def _terminate_process_tree(proc: subprocess.Popen) -> bool:
    """Best-effort tree termination; true only when the parent is no longer alive."""
    if proc.poll() is not None:
        return True
    if os.name == "nt":
        taskkill_failed = False
        try:
            result = subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
                timeout=10,
            )
            taskkill_failed = result.returncode != 0
        except (OSError, subprocess.SubprocessError):
            taskkill_failed = True
        if taskkill_failed or proc.poll() is None:
            script = (
                "$root=" + str(int(proc.pid)) + ";"
                "$all=Get-CimInstance Win32_Process;"
                "$ids=@($root);$changed=$true;"
                "while($changed){$changed=$false;foreach($p in $all){"
                "if($ids -contains [int]$p.ParentProcessId -and -not ($ids -contains [int]$p.ProcessId)){"
                "$ids += [int]$p.ProcessId;$changed=$true}}};"
                "$ids | Sort-Object -Descending | ForEach-Object {"
                "Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue}"
            )
            try:
                subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
                    timeout=15,
                )
            except (OSError, subprocess.SubprocessError):
                pass
        if proc.poll() is None:
            proc.kill()
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            if proc.poll() is None:
                proc.kill()
    return proc.poll() is not None


def _tail(value: str | bytes | None, limit: int = _OUTPUT_TAIL_CHARS) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value or "")[-max(0, int(limit)):]


def _run_cleanup_callback(callback: Callable[[], None]) -> bool:
    try:
        callback()
        return True
    except Exception:  # noqa: BLE001 - one cleanup must not block the others
        return False
