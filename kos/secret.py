"""Key material that is pinned in RAM and wiped when no longer needed.

``mlock`` keeps the pages out of swap; ``wipe`` overwrites them. Python cannot
guarantee that no copy of a secret ever exists (the interpreter may copy
immutable ``bytes``), which is one of the reasons the long-term plan is to port
this layer to Rust. Within that limit we keep the master key in exactly one
mutable, locked buffer.
"""

from __future__ import annotations

import ctypes

_libc = ctypes.CDLL(None, use_errno=True)


class SecretBytes:
    __slots__ = ("_buf", "_locked")

    def __init__(self, data: bytes | bytearray):
        self._buf = bytearray(data)
        self._locked = False
        if self._buf:
            addr, size = self._addr()
            self._locked = _libc.mlock(addr, size) == 0

    def _addr(self) -> tuple[ctypes.c_void_p, ctypes.c_size_t]:
        arr = (ctypes.c_char * len(self._buf)).from_buffer(self._buf)
        return ctypes.c_void_p(ctypes.addressof(arr)), ctypes.c_size_t(len(self._buf))

    @property
    def raw(self) -> bytearray:
        """The underlying buffer (no copy). Do not keep references to it."""
        if not self._buf:
            raise ValueError("secret has been wiped")
        return self._buf

    @property
    def locked(self) -> bool:
        return self._locked

    def wipe(self) -> None:
        if not self._buf:
            return
        ctypes.memset(self._addr()[0], 0, len(self._buf))
        if self._locked:
            _libc.munlock(*self._addr())
            self._locked = False
        self._buf = bytearray()

    def __len__(self) -> int:
        return len(self._buf)

    def __enter__(self) -> "SecretBytes":
        return self

    def __exit__(self, *exc) -> None:
        self.wipe()

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:
            pass

    def __repr__(self) -> str:
        return "<SecretBytes redacted>"
