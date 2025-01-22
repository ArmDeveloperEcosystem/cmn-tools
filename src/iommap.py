#!/usr/bin/python

"""
Reimplementation of the standard Python mmap module with better
control over access width, to support memory-mapped I/O.


Copyright (C) ARM Ltd. 2019.  All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

from __future__ import print_function

import os, ctypes, struct, errno


# Import the Python mmap module to get access to its constants.
import mmap as real_mmap
for x in real_mmap.__dict__:
    if x.startswith("PROT_") or x.startswith("MAP_"):
        globals()[x] = real_mmap.__dict__[x]
assert PROT_READ == real_mmap.PROT_READ
del real_mmap


_libc = ctypes.CDLL(None, use_errno=True)
_libc_mmap = _libc.mmap
_libc_mmap.restype = ctypes.c_void_p
_libc_mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_size_t]
_libc_munmap = _libc.munmap
_libc_munmap.restype = ctypes.c_int
_libc_munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]


class mmap:
    """
    Represent a single block of memory allocated by mmap.
    """
    def __init__(self, fno, size, flags=MAP_SHARED, prot=(PROT_WRITE|PROT_READ), offset=0):
        assert size > 0
        assert (size % os.sysconf("SC_PAGE_SIZE")) == 0
        assert offset >= 0
        self.size = size
        self.addr = _libc_mmap(0, size, prot, flags, fno, offset)
        if (self.addr & 0xfff) == 0xfff:
            # Mapping failed. Possible reasons:
            #  - CONFIG_IO_STRICT_DEVMEM and area is forbidden
            if ctypes.get_errno() == errno.EPERM:
                raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
            raise EnvironmentError

    def close(self):
        rc = _libc_munmap(self.addr, self.size)
        if rc != 0:
            raise OSError

    def seek(self, pos):
        self.pos = pos

    def read(self, nbytes):
        return self.__getslice__(self.pos, self.pos+nbytes)

    def __getitem__(self, item):
        # Python3 forwarder
        if isinstance(item, slice):
            assert item.step is None or item.step == 1
            return self.__getslice__(item.start, item.stop)
        else:
            raise TypeError("non-slice indexing not supported")

    def __getslice__(self, start, end):
        nbytes = end - start
        assert nbytes in [1,2,4,8], "invalid length for read: %u" % nbytes
        if nbytes == 1:
            x = ctypes.c_ubyte.from_address(self.addr + start)
            x = struct.pack("B", x.value)
        elif nbytes == 2:
            x = ctypes.c_ushort.from_address(self.addr + start)
            x = struct.pack("H", x.value)
        elif nbytes == 4:
            x = ctypes.c_uint.from_address(self.addr + start)
            x = struct.pack("I", x.value)
        elif nbytes == 8:
            x = ctypes.c_ulonglong.from_address(self.addr + start)
            x = struct.pack("Q", x.value)
        else:
            x = None
        return x

    def __setitem__(self, item, value):
        if isinstance(item, slice):
            assert item.step is None or item.step == 1
            self.__setslice__(item.start, item.stop, value)
        else:
            raise TypeError("non-slice indexing not supported")

    def __setslice__(self, start, end, value):
        nbytes = end - start
        assert len(value) == nbytes
        assert nbytes in [1,2,4,8], "invalid length for write: %u" % nbytes
        if nbytes == 1:
            x = ctypes.c_ubyte.from_address(self.addr + start)
            n = struct.unpack("B", value)[0]
        elif nbytes == 2:
            x = ctypes.c_ushort.from_address(self.addr + start)
            n = struct.unpack("H", value)[0]
        elif nbytes == 4:
            x = ctypes.c_uint.from_address(self.addr + start)
            n = struct.unpack("I", value)[0]
        elif nbytes == 8:
            x = ctypes.c_ulonglong.from_address(self.addr + start)
            n = struct.unpack("Q", value)[0]
        else:
            assert False
        x.value = n


if __name__ == "__main__":
    # Test by mapping this Python file, which starts "#!/usr/bin..."
    f = open(__file__, "rb")
    m = mmap(f.fileno(), os.sysconf("SC_PAGE_SIZE"), MAP_SHARED, PROT_READ, 0)
    s = m[4:8]
    assert s == "sr/b".encode(), "unexpected string: '%s'" % s
    m.close()
    f.close()
    print("mmap() test ok.")
