#!/usr/bin/python

"""
Map physical device memory. Base class for implementations on top of
Linux /dev/mem, ArmDS etc.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


class DevMemException(Exception):
    def __init__(self, dev, addr=None):
        assert isinstance(dev, DevMap), "unexpected device type: %s" % type(dev)
        self.dev = dev
        self.addr = addr


class DevMemWriteFailed(DevMemException):
    def __init__(self, dev, addr, data, ndata):
        DevMemException.__init__(self, dev, addr)
        self.data = data
        self.ndata = ndata

    def __str__(self):
        return "%s: at 0x%04x wrote 0x%x, read back 0x%x" % (self.dev, self.addr, self.data, self.ndata)


class DevMemOutOfBounds(DevMemException):
    def __init__(self, dev, addr):
        DevMemException.__init__(self, dev, addr)

    def __str__(self):
        return "%s: access at 0x%04x out of bounds" % (self.dev, self.addr)


class DevMemWriteProtected(DevMemException):
    def __init__(self, dev, addr, data):
        DevMemException.__init__(self, dev, addr)
        self.data = data

    def __str__(self):
        return "%s: at 0x%04x tried to write 0x%x when write-protected" % (self.dev, self.addr, self.data)


class DevMemNoSecure(DevMemException):
    def __init__(self, dev):
        DevMemException.__init__(self, dev)

    def __str__(self):
        return "%s: memory provider does not support Secure access" % (self.dev)


class DevMapFactory:
    """
    Abstract base class for a factory object that will return mappings to
    specified areas of memory, and own any common resources needed to
    construct and handle those mappings.
    """
    def __init__(self, write=False, check=False):
        self.writing = write
        self.checking = check

    def __str__(self):
        return "device"

    def map(self, pa, size, name=None, write=False):
        """
        Implementation should return an instance of a subclass of DevMap.
        """
        return Unimplemented()


class DevMap:
    """
    Abstract base class for a mapping object that maps a specific area of memory.
    """
    def __init__(self, pa, size, owner=None, name=None, write=False, check=None, secure=False):
        assert isinstance(owner, DevMapFactory)
        self.owner = owner
        if name is None:
            name = "%s:@0x%x" % (str(owner), pa)
        self.name = name
        self.pa = pa
        self.size = size
        self.writing = write
        self.checking = check
        self.is_secure = None
        self.set_secure_access(secure)

    def __str__(self):
        return self.name

    def ensure_writeable(self):
        """
        Upgrade this mapping object so that it's writeable.
        """
        if not self.writing:
            self._ensure_writeable()
            self.writing = True
        return self

    def _ensure_writeable(self):
        """
        Default implementation is to do nothing.
        A subclass might override to e.g. change memory protection.
        """
        pass

    def set_secure_access(self, is_secure):
        """
        Update the Secure/Non-Secure security setting.
        Subclass should override and raise DevMemNoSecure if it can't do this.
        """
        self.secure = is_secure

    def read64(self, off):
        if off >= self.size:
            raise DevMemOutOfBounds(self, off)
        return self._read64(off)

    def write64(self, off, val, check=None):
        """
        Write a 64-bit value to memory, with optional checking

        If the memory is currently not mapped writeable, we raise an exception.
        """
        if not self.writing:
            raise DevMemWriteProtected(self, off, val)
        if check is None:
            check = self.owner.checking
        self._write64(off, val)
        if check:
            rv = self._read64(off)
            if rv != val:
                raise DevMemWriteFailed(self, off, val, rv)

    def _read64(self, off):
        return Unimplemented()

    def _write64(self, off, val):
        return Unimplemented()

    def set32(self, off, val, check=None):
        old = self.read32(off)
        self.write32(off, old | val, check=check)
        return old & val

    def set64(self, off, val, check=None):
        old = self.read64(off)
        self.write64(off, old | val, check=check)
        return old & val

    def clr32(self, off, val, check=None):
        old = self.read32(off)
        self.write32(off, old & ~val, check=check)
        return old & val

    def clr64(self, off, val, check=None):
        old = self.read64(off)
        self.write64(off, old & ~val, check=check)
        return old & val


