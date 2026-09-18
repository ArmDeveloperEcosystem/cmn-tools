#!/usr/bin/python

"""
Map physical device memory. Base class for implementations on top of
Linux /dev/mem, ArmDS etc.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import operator
import sys


# Security states for memory access. Rather than inventing an enum,
# we use strings.
security_levels = ["NS", "S", "ROOT", "REALM"]


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


class DevMemOutOfBounds(DevMemException, IndexError):
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
    """
    Exception to indicate that the memory retargeting layer can't do the requested security level.
    """
    def __init__(self, dev, secure="S"):
        assert secure in security_levels   # only use this exception for valid (but unsupported) levels
        DevMemException.__init__(self, dev)
        self.requested_secure = secure

    def __str__(self):
        return "%s: memory provider does not support %s access" % (self.dev, self.requested_secure)


class SecureAccess(object):
    """
    Temporarily select an access security mode on a mapping or node.
    The device must provide set_secure_access(), returning its previous mode.
    Construction does not change the mode; use with SecureAccess(dev, "S").

    Restore the previous mode on exit, including after an exception. If both
    access and restoration fail, report the restoration failure and preserve
    the access exception. restore_failed lets callers distinguish that case
    from an unsupported access which they might otherwise handle as a fallback.

    Nested scopes must use separate context objects. An object can be reused
    after its previous scope has exited.
    """
    def __init__(self, dev, secure):
        self.dev = dev
        self.secure = secure
        self.old_secure = None
        self.restore_failed = False
        self._active = False

    def __enter__(self):
        """
        Select the requested mode and save the previous mode for this scope.
        """
        if self._active:
            raise RuntimeError("SecureAccess context is already active")
        self.restore_failed = False
        self.old_secure = self.dev.set_secure_access(self.secure)
        self._active = True
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Restore the previous mode without suppressing the scope's exception.
        """
        try:
            self.dev.set_secure_access(self.old_secure)
        except:
            # Unlike except BaseException, this also catches Java exceptions in Jython.
            self.restore_failed = True
            if exc_type is None:
                raise
            error = sys.exc_info()[1]
            try:
                print("%s: cannot restore %s access: %s" % (self.dev, self.old_secure, error), file=sys.stderr)
            except:
                # A failed diagnostic must not replace the access exception either.
                pass
        finally:
            self._active = False
        return False


class DevMapFactory:
    """
    Abstract base class for a factory object that will return mappings to
    specified areas of memory, and own any common resources needed to
    construct and handle those mappings.

    Subclass must:
      - implement map()
      - set is_local if mappings access memory on the local system
    """
    def __init__(self, write=False, check=False, is_local=None):
        self.writing = write
        self.checking = check
        if is_local is not None:
            self.is_local = is_local
        self.n_read = 0
        self.n_write = 0

    def __str__(self):
        """
        Name of the target - subclass can override
        """
        return "device"

    def __del__(self):
        # print("%s: %u reads, %u writes" % (self, self.n_read, self.n_write))
        pass

    def map(self, pa, size, name=None, write=False, verbose=0):
        """
        Implementation should return an instance of a subclass of DevMap.
        """
        raise NotImplementedError


class DevMap:
    """
    Abstract base class for a mapping object that maps a specific area of memory.

    Public accesses validate the complete logical range and natural alignment,
    enforce write permission, and account for backend attempts. Backends supply
    _read32/_read64 and _write32/_write64; they do not perform write readback.
    Check policy is selected by the call, then mapping, then factory setting.
    """
    def __init__(self, pa, size, owner=None, name=None, write=False, check=None, secure="NS", verbose=0):
        if not isinstance(owner, DevMapFactory):
            raise TypeError("mapping owner must be a DevMapFactory")
        pa = operator.index(pa)
        size = operator.index(size)
        if pa < 0 or pa >= (1 << 64):
            raise ValueError("mapping address must fit an unsigned 64-bit value")
        if size <= 0 or size > (1 << 64) - pa:
            raise ValueError("mapping size must be positive and fit the address range")
        self.owner = owner
        if name is None:
            name = "%s:@0x%x" % (str(owner), pa)
        self.name = name
        self.pa = pa
        self.size = size
        self.writing = write
        self.checking = check
        self.verbose_level = verbose
        self.secure = None
        self.set_secure_access(secure)

    def __str__(self):
        return self.name

    def verbose(self):
        return self.verbose_level

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

    def set_secure_access(self, secure):
        """
        Update the security setting and return the previous setting.
        Subclass should override _set_secure_access and raise DevMemNoSecure if
        it can't handle the requested level.
        """
        if secure not in security_levels:
            raise ValueError("Bad security %s: expected in %s" % (secure, str(security_levels)))
        self._set_secure_access(secure)
        o_secure = self.secure
        self.secure = secure
        return o_secure

    def _set_secure_access(self, secure):
        """
        This is really a check on whether the required security state is achieveable.
        Default implementation is to do nothing. Subclass might add a check.
        """
        pass

    def _check_access(self, off, width):
        off = operator.index(off)
        # Subtract the access width rather than forming a possibly overflowing
        # end offset. The mapping constructor has already checked pa + size.
        if off < 0 or off > self.size - width:
            raise DevMemOutOfBounds(self, off)
        if (self.pa + off) % width:
            raise ValueError("%s: unaligned %u-byte access at offset 0x%x" % (self, width, off))
        return off

    def _check_write(self, off, val, width):
        off = self._check_access(off, width)
        val = operator.index(val)
        if val < 0 or val >= (1 << (width * 8)):
            raise ValueError("write value must fit an unsigned %u-bit value" % (width * 8))
        if not self.writing:
            raise DevMemWriteProtected(self, off, val)
        return off, val

    def _read_access(self, off, width, read):
        off = self._check_access(off, width)
        self.owner.n_read += 1
        return read(off)

    def _write_access(self, off, val, width, write, read, check):
        off, val = self._check_write(off, val, width)
        if check is None:
            check = self.checking
        if check is None:
            check = self.owner.checking
        self.owner.n_write += 1
        write(off, val)
        if check:
            # Use the public reader so readback is included in n_read.
            rv = read(off)
            if rv != val:
                raise DevMemWriteFailed(self, off, val, rv)

    def read32(self, off):
        return self._read_access(off, 4, self._read32)

    def read64(self, off):
        return self._read_access(off, 8, self._read64)

    def write32(self, off, val, check=None):
        self._write_access(off, val, 4, self._write32, self.read32, check)

    def write64(self, off, val, check=None):
        self._write_access(off, val, 8, self._write64, self.read64, check)

    def _read32(self, off):
        raise NotImplementedError

    def _read64(self, off):
        raise NotImplementedError

    def _write32(self, off, val):
        raise NotImplementedError

    def _write64(self, off, val):
        raise NotImplementedError

    def set32(self, off, val, check=None):
        off, val = self._check_write(off, val, 4)
        old = self.read32(off)
        self.write32(off, old | val, check=check)
        return old & val

    def set64(self, off, val, check=None):
        off, val = self._check_write(off, val, 8)
        old = self.read64(off)
        self.write64(off, old | val, check=check)
        return old & val

    def clr32(self, off, val, check=None):
        off, val = self._check_write(off, val, 4)
        old = self.read32(off)
        self.write32(off, old & ~val, check=check)
        return old & val

    def clr64(self, off, val, check=None):
        off, val = self._check_write(off, val, 8)
        old = self.read64(off)
        self.write64(off, old & ~val, check=check)
        return old & val

