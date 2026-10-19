"""Cross-process lock for the local license database; standard library only."""
import os
import threading
import time


class FileMutex:
    """Serialize keygen and server transactions on the same local disk.

    Not a network/distributed lock. All writers must use this same lock file.
    """
    def __init__(self, path, timeout=15):
        self.path, self.timeout = path, timeout
        self.thread_lock = threading.RLock()
        self.local = threading.local()

    def __enter__(self):
        self.thread_lock.acquire()
        try:
            depth = getattr(self.local, 'depth', 0)
            if depth:
                self.local.depth = depth + 1
                return self
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            fh = open(self.path, 'a+b')
            if os.path.getsize(self.path) == 0:
                fh.write(b'0')
                fh.flush()
            end = time.monotonic() + self.timeout
            while True:
                try:
                    fh.seek(0)
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= end:
                        fh.close()
                        raise TimeoutError('License database is busy; retry the operation.')
                    time.sleep(0.05)
            self.local.fh, self.local.depth = fh, 1
            return self
        except Exception:
            self.thread_lock.release()
            raise

    def __exit__(self, *_):
        self.local.depth -= 1
        try:
            if self.local.depth == 0:
                fh = self.local.fh
                try:
                    fh.seek(0)
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                finally:
                    fh.close()
        finally:
            self.thread_lock.release()
