"""Safety primitives for shxrx 3.3. Standard library only; no actions at import.

Cleanup is conservative, not a security sandbox: filesystem races by another
privileged process cannot be ruled out. Never run recursive cleaning on an
untrusted directory as administrator. Registry undo covers only reg_set calls.
"""
import base64
import concurrent.futures
import fnmatch
import glob
import hashlib
import json
import os
import stat
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path


def atomic_json(path, value):
    """Durably write a unique sibling then replace; never truncate the live file."""
    path = os.path.abspath(os.fspath(path))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + os.path.basename(path) + '-', dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            json.dump(value, out, ensure_ascii=False, indent=2, allow_nan=False)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def read_json(path, default=None):
    try:
        with open(path, encoding='utf-8') as src:
            return json.load(src)
    except (OSError, ValueError):
        return default


def norm(path):
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def inside(path, root):
    try:
        return os.path.commonpath([norm(path), norm(root)]) == norm(root)
    except (ValueError, OSError):
        return False


def linked(path):
    """Reject symlinks and ALL Windows reparse points, including on Python 3.10."""
    st = os.lstat(path)
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, 'st_file_attributes', 0) & 0x400)


def clean_chain(path, root):
    if not inside(path, root):
        return False
    cur = Path(os.path.abspath(path))
    # Include every ancestor, not just the leaf: a replaced parent must not be followed.
    while True:
        try:
            if linked(cur):
                return False
        except OSError:
            return False
        if cur.parent == cur:
            return True
        cur = cur.parent


def identity(path):
    st = os.stat(path, follow_symlinks=False)
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


@dataclass(frozen=True)
class Candidate:
    path: str
    root: str
    signature: tuple

    @property
    def size(self):
        return self.signature[2]


@dataclass
class CleanupPlan:
    files: list
    skipped: int = 0
    errors: int = 0
    cancelled: bool = False
    truncated: bool = False

    @property
    def bytes(self):
        return sum(f.size for f in self.files)


class SafeCleaner:
    """Preview old regular files, then delete only unchanged previewed files.

    Never removes directories, reparse points, hardlinks, live/recent files, or
    excluded trees. max_files bounds preview memory. Cleanup is irreversible.
    """
    def __init__(self, min_age_hours=48, excluded=(), max_files=100000):
        self.min_age = max(1.0, float(min_age_hours)) * 3600
        self.excluded = tuple(norm(p) for p in excluded)
        self.max_files = max(1, int(max_files))

    def excluded_path(self, path):
        return any(inside(path, p) for p in self.excluded)

    def plan(self, entries, stop=None):
        plan, seen = CleanupPlan([]), set()
        cutoff = time.time() - self.min_age
        for base, pattern in entries:
            if not base or not os.path.isabs(base):
                plan.skipped += 1
                continue
            # Wildcards are allowed in the base (e.g. Firefox profiles), not traversal.
            if '..' in Path(base).parts or os.path.isabs(pattern) or '..' in Path(pattern).parts:
                plan.skipped += 1
                continue
            for root in glob.iglob(base):
                root = norm(root)
                if root == os.path.dirname(root) or self.excluded_path(root) or not clean_chain(root, root):
                    plan.skipped += 1
                    continue
                stack = [(p, root) for p in glob.iglob(os.path.join(glob.escape(root), pattern))]
                while stack:
                    if stop is not None and stop.is_set():
                        plan.cancelled = True
                        return plan
                    path, allowed = stack.pop()
                    if self.excluded_path(path) or not clean_chain(path, allowed):
                        plan.skipped += 1
                        continue
                    try:
                        st = os.lstat(path)
                        if stat.S_ISDIR(st.st_mode):
                            with os.scandir(path) as it:
                                for e in it:
                                    stack.append((e.path, allowed))
                        elif stat.S_ISREG(st.st_mode):
                            if max(st.st_mtime, st.st_atime) > cutoff or st.st_nlink != 1:
                                plan.skipped += 1
                                continue
                            sig = identity(path)
                            key = sig[:2] if sig[1] else norm(path)
                            if key in seen:
                                continue
                            seen.add(key)
                            plan.files.append(Candidate(norm(path), allowed, sig))
                            if len(plan.files) >= self.max_files:
                                plan.truncated = True
                                return plan
                        else:
                            plan.skipped += 1
                    except OSError:
                        plan.errors += 1
        return plan

    def execute(self, plan, stop=None):
        if plan.cancelled:
            return {'deleted': 0, 'bytes': 0, 'skipped': len(plan.files), 'errors': 0}
        result = {'deleted': 0, 'bytes': 0, 'skipped': 0, 'errors': 0}
        for f in plan.files:
            if stop is not None and stop.is_set():
                break
            try:
                if (self.excluded_path(f.path) or not clean_chain(f.path, f.root)
                        or identity(f.path) != f.signature or os.lstat(f.path).st_nlink != 1
                        or max(os.lstat(f.path).st_mtime, os.lstat(f.path).st_atime) > time.time() - self.min_age):
                    result['skipped'] += 1
                    continue
                os.unlink(f.path)
                result['deleted'] += 1
                result['bytes'] += f.size
            except OSError:
                result['errors'] += 1
        return result


class AuditLog:
    """Bounded JSONL operation history, protected across threads of this process."""
    def __init__(self, path, max_bytes=2 * 1024 * 1024):
        self.path = path
        self.max_bytes = max_bytes
        self.lock = threading.RLock()

    def record(self, action, **details):
        row = {'time': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'action': action, **details}
        with self.lock:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            if os.path.exists(self.path) and os.path.getsize(self.path) > self.max_bytes:
                os.replace(self.path, self.path + '.1')
            with open(self.path, 'a', encoding='utf-8') as out:
                out.write(json.dumps(row, ensure_ascii=False) + '\n')
        return row

    def recent(self, limit=50):
        with self.lock:
            try:
                from collections import deque
                with open(self.path, encoding='utf-8') as src:
                    lines = deque(src, maxlen=limit)
                result = []
                for line in lines:
                    try:
                        result.append(json.loads(line))
                    except ValueError:
                        continue
                return result
            except OSError:
                return []


class JobPool:
    """Bounded executor: limits active workers AND queued submissions."""
    def __init__(self, workers=4, pending=12):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix='shxrx')
        self.slots = threading.BoundedSemaphore(pending)
        self.lock = threading.Lock()
        self.closed = False

    def submit(self, fn):
        with self.lock:
            if self.closed or not self.slots.acquire(blocking=False):
                return None
            try:
                future = self.executor.submit(fn)
                future.add_done_callback(lambda _: self.slots.release())
                return future
            except Exception:
                self.slots.release()
                raise

    def shutdown(self):
        with self.lock:
            self.closed = True
            self.executor.shutdown(wait=False, cancel_futures=True)


def file_digest(path, stop=None):
    h = hashlib.blake2b(digest_size=32)
    with open(path, 'rb') as src:
        while True:
            if stop is not None and stop.is_set():
                raise InterruptedError('Cancelled')
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


def delete_duplicate(path, keeper, stop=None):
    """Recheck identities and contents before deleting; never remove the keeper."""
    path, keeper = norm(path), norm(keeper)
    if path == keeper or not clean_chain(path, os.path.dirname(path)) or not clean_chain(keeper, os.path.dirname(keeper)):
        raise ValueError('A duplicate path is unsafe or the keeper is missing.')
    a, b = identity(path), identity(keeper)
    if a[:2] == b[:2]:
        raise ValueError('Hardlinks are not independent duplicate files.')
    if a[2] != b[2] or not stat.S_ISREG(os.lstat(path).st_mode) or not stat.S_ISREG(os.lstat(keeper).st_mode):
        raise ValueError('Files changed since the scan.')
    if file_digest(path, stop) != file_digest(keeper, stop):
        raise ValueError('Files no longer have identical contents.')
    if (identity(path) != a or identity(keeper) != b
            or not clean_chain(path, os.path.dirname(path)) or not clean_chain(keeper, os.path.dirname(keeper))):
        raise ValueError('A file changed while being verified.')
    if stop is not None and stop.is_set():
        raise InterruptedError('Cancelled')
    os.unlink(path)
    return a[2]


def _encode(value):
    return {'binary': base64.b64encode(value).decode('ascii')} if isinstance(value, bytes) else value


def _decode(value):
    return base64.b64decode(value['binary']) if isinstance(value, dict) and 'binary' in value else value


_journal_locks = {}
_journal_locks_guard = threading.Lock()


class RegistryJournal:
    """Write-ahead backups for changes through the application's reg_set helper.

    Commands, service changes, deletions, and third-party writes are NOT covered.
    Undo refuses conflicting current values. Journals persist in the data folder.
    """
    def __init__(self, path, registry=None):
        if registry is None:
            import winreg as registry
        self.reg = registry
        self.path = path
        with _journal_locks_guard:
            self.lock = _journal_locks.setdefault(norm(path), threading.RLock())

    def rows(self):
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, encoding='utf-8') as src:
                rows = json.load(src)
            if not isinstance(rows, list):
                raise ValueError('Expected journal array')
            return rows
        except (ValueError, TypeError) as e:
            raise ValueError('Registry journal is damaged; restore its backup before continuing.') from e

    def hive_name(self, hive):
        for name in ('HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS', 'HKEY_CLASSES_ROOT'):
            if hive == getattr(self.reg, name):
                return name
        raise ValueError('Unsupported registry hive')

    def current(self, hive, path, name):
        try:
            with self.reg.OpenKey(hive, path, 0, self.reg.KEY_QUERY_VALUE) as k:
                value, kind = self.reg.QueryValueEx(k, name)
            return {'exists': True, 'value': _encode(value), 'kind': kind}
        except FileNotFoundError:
            return {'exists': False}

    def set(self, hive, path, name, value, kind):
        with self.lock:
            rows = self.rows()
            before = self.current(hive, path, name)
            after = {'exists': True, 'value': _encode(value), 'kind': kind}
            if before == after:
                return
            row = {'hive': self.hive_name(hive), 'path': path, 'name': name, 'before': before,
                   'after': after, 'time': time.time(), 'state': 'pending'}
            rows.append(row)
            # Fail closed: no write if its backup cannot be saved.
            atomic_json(self.path, rows)
            with self.reg.CreateKeyEx(hive, path, 0, self.reg.KEY_SET_VALUE) as k:
                self.reg.SetValueEx(k, name, 0, kind, value)
            row['state'] = 'applied'
            atomic_json(self.path, rows)

    def undo(self):
        restored, conflicts, errors = 0, 0, 0
        with self.lock:
            rows = self.rows()
            for row in reversed(rows):
                if row['state'] not in ('applied', 'pending'):
                    continue
                hive = getattr(self.reg, row['hive'])
                try:
                    now = self.current(hive, row['path'], row['name'])
                    if now == row['before']:
                        row['state'] = 'undone'
                    elif now != row['after']:
                        conflicts += 1
                        continue
                    else:
                        if row['before']['exists']:
                            with self.reg.CreateKeyEx(hive, row['path'], 0, self.reg.KEY_SET_VALUE) as k:
                                self.reg.SetValueEx(k, row['name'], 0, row['before']['kind'], _decode(row['before']['value']))
                        else:
                            with self.reg.OpenKey(hive, row['path'], 0, self.reg.KEY_SET_VALUE) as k:
                                self.reg.DeleteValue(k, row['name'])
                        row['state'] = 'undone'
                        restored += 1
                    atomic_json(self.path, rows)
                except OSError:
                    errors += 1
        return {'restored': restored, 'conflicts': conflicts, 'errors': errors}
