#!/usr/bin/python

"""
Allocate physical memory

---
Copyright (C) ARM Ltd. 2022. All rights reserved.

SPDX-License-Identifer: Apache 2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
---

Allocate some physical memory.

This is achieved by
 - using mmap() to allocate some virtual memory
 - using mlock() to keep the memory resident in RAM
 - finding out the physical address(es) of the memory

Note that in a VM, the 'physical' address space is that presented by the hypervisor.
mlock() does not prevent page migration and is not a DMA pinning mechanism.

contiguous=True populates and verifies the entire allocation, failing if any
page is absent, its PFN is unavailable, or its PA is not consecutive. It saves
a physical mapping snapshot. check_pa() rereads every page and reports observed
changes; close() also checks before unlocking. This can miss transient migration
and cannot make DMA safe. The caller must stop the device before checking or
closing the allocation.

On AArch64 Linux, cache_clean() and cache_clean_invalidate() build a small C
library with cc on first use and load it with ctypes. They maintain data caches
to the Point of Coherency (PoC), including a completion barrier. The platform
must allow these instructions in userspace, and PoC must be sufficient for the
device being used. These operations do not establish a stable DMA address.

For a buffer that a non-coherent device will write, clean and invalidate before
starting the device. Do not access the buffer while the device owns it. Once
the device has stopped and its writes have completed, clean and invalidate
again before reading. This is safe only if no CPU has dirtied the buffer's
cache lines during device ownership; cleaning dirty lines then could overwrite
the device's data. All users of a shared cache line must follow this protocol.
"""

from __future__ import print_function

import ctypes
import errno
import sys
import os
import mmap
import operator
import shutil
import subprocess
import tempfile
import threading


import pagemap


_MAP_LOCKED  = 0x2000
_MAP_HUGETLB = 0x40000
_MADV_HUGEPAGE = 14


libc = ctypes.CDLL(None, use_errno=True)
libc_mmap = libc.mmap
libc_mmap.restype = ctypes.c_void_p
libc_mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulonglong]
libc_munmap = libc.munmap
libc_munmap.restype = ctypes.c_int
libc_munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc_mlock = libc.mlock
libc_mlock.restype = ctypes.c_int
libc_mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc_munlock = libc.munlock
libc_munlock.restype = ctypes.c_int
libc_munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc_madvise = libc.madvise
libc.madvise.restype = ctypes.c_int
libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]


HUGE_NOT      = 0    # don't try to use huge pages
HUGE_ADVISE   = 1    # advise use of THP
HUGE_ALLOC    = 2    # allocate from huge pool, else advise
HUGE_FORCE    = 3    # allocate from huge pool or fail


_SIZE_MAX = (1 << (ctypes.sizeof(ctypes.c_size_t) * 8)) - 1
_POINTER_MAX = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1


_cache_maintenance_c = r"""
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__aarch64__)
#error Cache maintenance requires AArch64
#endif

/* Arm A-profile Architecture Reference Manual, DDI 0487:
 * CTR_EL0.DminLine, DC CVAC, DC CIVAC and DSB.
 * CVAC and CIVAC operate to PoC; IVAC is not available at EL0.
 */
static int cache_maintain(void *base, size_t size, int invalidate)
{
    uintptr_t address = (uintptr_t)base;
    uintptr_t last, line_size;
    uint64_t ctr;

    if (size == 0)
        return 0;
    if (base == NULL)
        return EINVAL;
    if (size - 1 > UINTPTR_MAX - address)
        return EOVERFLOW;

    __asm__ volatile("mrs %0, ctr_el0" : "=r" (ctr));
    line_size = (uintptr_t)4 << ((ctr >> 16) & 15);
    last = (address + size - 1) & ~(line_size - 1);
    address &= ~(line_size - 1);
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) {
        if (invalidate)
            __asm__ volatile("dc civac, %0" :: "r" (address) : "memory");
        else
            __asm__ volatile("dc cvac, %0" :: "r" (address) : "memory");
        if (address == last)
            break;
        address += line_size;
    }
    __asm__ volatile("dsb sy" ::: "memory");
    return 0;
}

int physmem_cache_clean(void *base, size_t size)
{
    return cache_maintain(base, size, 0);
}

int physmem_cache_clean_invalidate(void *base, size_t size)
{
    return cache_maintain(base, size, 1);
}
"""


_cache_probe_python = """
import ctypes
import resource
import sys

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
library = ctypes.CDLL(sys.argv[1])
buffer = ctypes.create_string_buffer(256)
for operation in (library.physmem_cache_clean, library.physmem_cache_clean_invalidate):
    operation.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    operation.restype = ctypes.c_int
    if operation(ctypes.addressof(buffer), ctypes.sizeof(buffer)) != 0:
        sys.exit(1)
"""


_cache_library = None
_cache_library_lock = threading.Lock()


def _cache_command(command, description, input_data=None):
    """
    Run a helper build or probe, reaping the child even after interruption.
    """
    process = subprocess.Popen(command, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               shell=False)
    try:
        out, err = process.communicate(input_data)
    except BaseException:
        try:
            process.kill()
        except OSError:
            pass
        process.communicate()
        raise
    if process.returncode != 0:
        raise OSError("%s failed (exit %s): %s" %
                      (description, process.returncode, err.decode("utf-8", "replace").strip()))


def _progress(verbose, message):
    if verbose:
        print("physmem: %s" % message, file=sys.stderr)
        sys.stderr.flush()


def _build_cache_library(verbose=0):
    """
    Compile, probe and load the helper in a private temporary directory.
    Linux retains the loaded mapping after the shared object is unlinked.
    """
    if not sys.platform.startswith("linux") or os.uname()[4] not in ("aarch64", "arm64"):
        raise ValueError("cache maintenance requires AArch64 Linux")
    directory = tempfile.mkdtemp(prefix="physmem-cache-")
    try:
        fd, path = tempfile.mkstemp(suffix=".so", dir=directory)
        os.close(fd)
        _progress(verbose, "building cache maintenance shared library with cc: %s" % path)
        _cache_command(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC",
                        "-shared", "-xc", "-", "-o", path],
                       "cache helper compilation", _cache_maintenance_c.encode("ascii"))
        _progress(verbose, "cache maintenance library built; probing load and cache instructions in a child process")
        # Instruction access can be trapped by the OS or hypervisor. Probe in
        # another process so that SIGILL does not terminate the calling tool.
        _cache_command([sys.executable, "-c", _cache_probe_python, path],
                       "userspace cache maintenance probe")
        _progress(verbose, "cache instruction probe passed; loading shared library with ctypes: %s" % path)
        library = ctypes.CDLL(path)
        library.physmem_cache_clean.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        library.physmem_cache_clean.restype = ctypes.c_int
        library.physmem_cache_clean_invalidate.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        library.physmem_cache_clean_invalidate.restype = ctypes.c_int
        _progress(verbose, "cache maintenance shared library loaded")
        return library
    finally:
        shutil.rmtree(directory)


def _get_cache_library(verbose=0):
    """
    Build once per process, only when a nonempty cache operation is requested.
    """
    global _cache_library
    with _cache_library_lock:
        if _cache_library is None:
            _cache_library = _build_cache_library(verbose=verbose)
        return _cache_library


class PhysMem:
    """
    A contiguous block of virtual addresses which we can lock into physical memory.
    This may span multiple pages, and be discontiguous in physical memory.

    We can try allocating with MAP_HUGETLB, but this may fail if the system hasn't
    been set up with any huge pages.

    Or, we can allocate (without using MAP_LOCKED) and then use madvise to request
    transparent huge pages. But the VA range has already been allocated by that point.

    Use HUGE_ALLOC to try the huge page pool and then transparent huge pages,
    or HUGE_FORCE to require the huge page pool. Even with huge pages, a block
    spanning multiple huge pages must pass the contiguity check.
    """
    def __init__(self, size, lock=True, huge=HUGE_NOT, contiguous=False, init=None,
                 verbose=0):
        self.va = None
        self.verbose = verbose
        size = operator.index(size)
        if size <= 0:
            raise ValueError("allocation size must be positive")
        self.requested_size = size
        self.page_size = os.sysconf("SC_PAGE_SIZE")
        self.is_locked = False
        self._pa_snapshot = None
        self.pa_range_cached = None
        self.ctype_buffer_cached = None
        # Round up requested page size
        if (size % self.page_size) != 0:
            size += (self.page_size - (size % self.page_size))
        if size > min(_SIZE_MAX, _POINTER_MAX):
            raise ValueError("allocation size does not fit size_t or a pointer")
        self.alloc_size = size
        self.pa_map = pagemap.PAMap()        # map of our own process
        flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
        if lock:
            flags |= _MAP_LOCKED
        if huge >= HUGE_ALLOC:
            huge_page_size = default_huge_page_size()
            if huge_page_size is not None:
                flags |= _MAP_HUGETLB
                size = ((size + huge_page_size - 1) // huge_page_size) * huge_page_size
                if size > min(_SIZE_MAX, _POINTER_MAX):
                    raise ValueError("huge allocation size does not fit size_t or a pointer")
            elif huge == HUGE_FORCE:
                raise OSError(errno.ENOTSUP, "default huge page size is unavailable")
        _progress(self.verbose, "allocating %u bytes with mmap (huge pages=%s, MAP_LOCKED=%s)" %
                  (size, bool(flags & _MAP_HUGETLB), bool(flags & _MAP_LOCKED)))
        va = libc_mmap(0, size, mmap.PROT_WRITE|mmap.PROT_READ, flags, -1, 0)
        if va == ctypes.c_void_p(-1).value:
            if (flags & _MAP_HUGETLB) != 0:
                # Failed to allocate with MAP_HUGETLB. Either there are none in the pool or
                # they are all in use.
                if huge == HUGE_FORCE:
                    error = ctypes.get_errno()
                    raise OSError(error, "huge page mmap failed: %s" % os.strerror(error))
                # retry with THP
                flags &= ~_MAP_HUGETLB
                flags &= ~_MAP_LOCKED
                size = self.alloc_size
                _progress(self.verbose, "huge page mmap failed; retrying %u bytes with ordinary pages" % size)
                va = libc_mmap(0, size, mmap.PROT_WRITE|mmap.PROT_READ, flags, -1, 0)
            if va == ctypes.c_void_p(-1).value:
                error = ctypes.get_errno()
                raise OSError(error, "mmap failed: %s (size=0x%x flags=0x%x)" %
                              (os.strerror(error), size, flags))
        self.va = va
        self.alloc_size = size
        try:
            _progress(self.verbose, "allocated VA 0x%x, %u bytes" % (self.va, self.alloc_size))
            if (flags & _MAP_HUGETLB) == 0 and huge >= HUGE_ADVISE:
                _progress(self.verbose, "requesting transparent huge pages")
                self.madvise(_MADV_HUGEPAGE)
            if lock:
                _progress(self.verbose, "locking allocation with mlock")
                self.lock()
                _progress(self.verbose, "allocation locked")
            if init is not None:
                b = self.buffer()
                for i in range(0, self.alloc_size):
                    b[i] = init
            if contiguous:
                # Write-fault every private page before looking up PFNs, so
                # that an anonymous zero page cannot masquerade as backing RAM.
                _progress(self.verbose, "populating every page before physical address lookup")
                for offset in range(0, self.alloc_size, self.page_size):
                    byte = ctypes.c_ubyte.from_address(self.va + offset)
                    byte.value = byte.value
                _progress(self.verbose, "reading physical addresses from pagemap and checking contiguity")
                pages = self.snapshot_pa()
                for i, pa in enumerate(pages):
                    if pa != pages[0] + i * self.page_size:
                        self._pa_snapshot = None
                        raise ValueError("allocation is not physically contiguous at VA 0x%x" %
                                         (self.va + i * self.page_size))
                _progress(self.verbose, "verified contiguous PA 0x%x, %u bytes (%u pages of %u bytes)" %
                          (pages[0], self.alloc_size, len(pages), self.page_size))
        except BaseException:
            self.close()
            raise

    def lock(self):
        """
        Lock the allocated VA page range into physical memory. This will map any currently unmapped pages.
        """
        assert self.va is not None
        rc = libc_mlock(self.va, self.alloc_size)
        if rc != 0:
            error = ctypes.get_errno()
            raise OSError(error, "mlock failed: %s" % os.strerror(error))
        self.is_locked = True
        self.pa_range_cached = None

    def unlock(self):
        assert self.is_locked, "block is already unlocked"
        rc = libc_munlock(self.va, self.alloc_size)
        self.is_locked = False
        self.pa_range_cached = None

    def madvise(self, option, start=None, length=None):
        if start is None:
            start = self.va
        if length is None:
            length = self.va + self.alloc_size - start
        rc = libc_madvise(start, length, _MADV_HUGEPAGE)
        if rc != 0:
            raise OSError
        return rc

    def buffer(self):
        assert self.alloc_size > 0
        if self.ctype_buffer_cached is None:
            self.ctype_buffer_cached = (ctypes.c_char * self.alloc_size).from_address(self.va)
        assert len(self.ctype_buffer_cached.raw) == self.alloc_size
        return self.ctype_buffer_cached

    def _cache_range(self, offset, size):
        """
        Validate the entire range before converting addresses and sizes to C.
        """
        if self.va is None:
            raise ValueError("memory block is closed")
        offset = operator.index(offset)
        if offset < 0 or offset > self.alloc_size:
            raise IndexError("cache offset is outside the allocation")
        if size is None:
            size = self.alloc_size - offset
        size = operator.index(size)
        if size < 0:
            raise ValueError("cache size must not be negative")
        if size > self.alloc_size - offset:
            raise IndexError("cache range is outside the allocation")
        address = self.va + offset
        if (size > _SIZE_MAX or address < 0 or address > _POINTER_MAX or
                (size and size - 1 > _POINTER_MAX - address)):
            raise ValueError("cache range does not fit size_t or a pointer")
        return address, size

    def cache_clean(self, offset=0, size=None):
        """
        Write back dirty cache lines to PoC and wait for completion.
        The default range is the whole allocation, including page rounding.
        Partial cache lines are maintained in full: the caller must own all
        affected cache lines and prevent concurrent accesses and unmapping.
        """
        address, size = self._cache_range(offset, size)
        if size:
            rc = _get_cache_library(verbose=self.verbose).physmem_cache_clean(address, size)
            if rc != 0:
                raise OSError(rc, os.strerror(rc))

    def cache_clean_invalidate(self, offset=0, size=None):
        """
        Write back and invalidate cache lines to PoC and wait for completion.
        Range and ownership rules are the same as for cache_clean(). After
        device writes, no CPU may have dirtied these lines since the preceding
        clean and invalidate; see the module's device ownership protocol.
        """
        address, size = self._cache_range(offset, size)
        if size:
            rc = _get_cache_library(verbose=self.verbose).physmem_cache_clean_invalidate(address, size)
            if rc != 0:
                raise OSError(rc, os.strerror(rc))

    def pa_range(self, refresh=False):
        """
        Return the list of physical page ranges for this memory block.
        Results are cached; use refresh=True to reread the current mapping.
        """
        if self.va is None:
            raise ValueError("memory block is closed")
        if self.pa_range_cached is None or refresh:
            self.pa_range_cached = self.pa_map.pa_range(self.va, self.alloc_size)
        return self.pa_range_cached

    def pa(self, refresh=False):
        pr = self.pa_range(refresh=refresh)
        if pr is None:
            return None
        elif len(pr) == 1:
            return pr[0].pa()
        else:
            return None

    def is_contiguous(self, refresh=False):
        """
        Return true if the block is in physically contiguous memory.
        """
        ranges = self.pa_range(refresh=refresh)
        return (len(ranges) == 1 and ranges[0].is_mapped() and
                ranges[0].size == self.alloc_size and ranges[0].pa() is not None)

    def _read_pa_pages(self):
        """
        Read every page's physical address, bypassing the range cache.
        """
        if self.va is None:
            raise ValueError("memory block is closed")
        pages = []
        for offset in range(0, self.alloc_size, self.page_size):
            entry = self.pa_map.entry(self.va + offset)
            if entry is None:
                raise OSError(errno.EIO, "cannot read pagemap for VA 0x%x" % (self.va + offset))
            pages.append(entry.pa())
        return tuple(pages)

    def snapshot_pa(self):
        """
        Save the current per-page PAs for later checks. All pages must be present.
        contiguous=True does this automatically after populating the allocation.
        """
        pages = self._read_pa_pages()
        if None in pages:
            raise ValueError("allocation is not entirely resident in physical memory")
        self._pa_snapshot = pages
        return pages

    def check_pa(self, file=None):
        """
        Report changed page mappings and return False on changes or read errors.
        A True result only means no change was observed between two snapshots.
        Stop all device accesses before checking. The initial snapshot is retained.
        """
        if self._pa_snapshot is None:
            raise ValueError("no physical address snapshot has been taken")
        if self.va is None:
            raise ValueError("memory block is closed")
        if file is None:
            file = sys.stderr
        try:
            current = self._read_pa_pages()
        except OSError as error:
            print("physical address check failed: %s" % error, file=file)
            return False
        changed = 0
        for i, (old, new) in enumerate(zip(self._pa_snapshot, current)):
            if old != new:
                changed += 1
                if changed <= 8:
                    print("physical address changed at VA 0x%x: PA 0x%x -> %s" %
                          (self.va + i * self.page_size, old,
                           "<unmapped>" if new is None else "0x%x" % new), file=file)
        if changed:
            print("physical address check: %u of %u pages changed; "
                  "device writes may have used obsolete addresses" %
                  (changed, len(current)), file=file)
        return changed == 0

    def is_in_memory(self):
        """
        Return true if the block is entirely in memory.
        """
        for r in self.pa_range():
            if not r.is_mapped():
                return False
        return True

    def close(self):
        if self.va is not None:
            try:
                if self._pa_snapshot is not None:
                    self.check_pa()
            finally:
                if self.is_locked:
                    self.unlock()
                if libc_munmap(self.va, self.alloc_size) != 0:
                    error = ctypes.get_errno()
                    raise OSError(error, "munmap failed: %s" % os.strerror(error))
                self.va = None
                self.pa_range_cached = None
                self.ctype_buffer_cached = None

    def __del__(self):
        self.close()

    def __str__(self):
        s = "size:0x%x" % self.alloc_size
        if self.va is not None:
            s += ",VA:0x%x" % self.va
            # Find physical address of start TBD: might not be contiguous in PA. Should find range of PAs.
            pa = self.pa_map.pa(self.va)
            if pa is not None:
                s += ",PA:0x%x" % pa
            if not self.is_contiguous():
                s += ",discontiguous"
            if not self.is_in_memory():
                s += ",unalloc"
            if self.is_locked:
                s += ",locked"
        return "{%s}" % s


def _readn(fn):
    """
    Read a number from a file in e.g. sysfs
    """
    with open(fn) as f:
        return int(f.read().strip())


def n_sys_huge_pages():
    """
    Return the number of huge pages in the pool for MAP_HUGETLB.
    """
    return _readn("/proc/sys/vm/nr_hugepages")


def default_huge_page_size():
    """
    Return the default hugetlb page size in bytes, or None without hugetlb support.
    Linux Documentation/admin-guide/mm/hugetlbpage.rst defines Hugepagesize.
    """
    with open("/proc/meminfo") as f:
        for line in f:
            fields = line.split()
            if fields and fields[0] == "Hugepagesize:":
                if len(fields) != 3 or fields[2] != "kB":
                    raise ValueError("invalid Hugepagesize in /proc/meminfo")
                size = int(fields[1]) * 1024
                if size <= 0 or size % os.sysconf("SC_PAGE_SIZE") != 0:
                    raise ValueError("invalid huge page size: %s" % size)
                return size
    return None


def show_huge_page_config():
    print("Huge pages:")
    print("  THP: %s" % open("/sys/kernel/mm/transparent_hugepage/enabled").read().strip())
    print("  nr_hugepages: %u" % n_sys_huge_pages())
    hpc = "/sys/kernel/mm/hugepages"
    hpsizes = sorted([int(x[10:-2]) for x in os.listdir(hpc)])
    for ps in hpsizes:
        d = os.path.join(hpc, "hugepages-%ukB" % ps)
        assert os.path.isdir(d)
        pnr = _readn(os.path.join(d, "nr_hugepages"))
        pfree = _readn(os.path.join(d, "free_hugepages"))
        print("  %9ukB %9u %9u" % (ps, pnr, pfree))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="test physical memory allocation")
    parser.add_argument("--pages", type=int, default=3, help="number of pages to allocate")
    parser.add_argument("--blocks", type=int, default=1, help="number of blocks")
    parser.add_argument("--huge", type=int, default=0, help="0: don't care, 1: if available, 2: force")
    parser.add_argument("--no-lock", action="store_true", help="don't lock block in memory")
    parser.add_argument("--set-huge", type=int, help="set OS global number of huge pages")
    parser.add_argument("--show-huge", action="store_true", help="show OS global huge page configuration")
    opts = parser.parse_args()
    if opts.show_huge:
        show_huge_page_config()
    if opts.set_huge is not None:
        with open("/proc/sys/vm/nr_hugepages", "w") as f:
            f.write("%u\n" % opts.set_huge)
        with open("/proc/sys/vm/nr_hugepages") as f:
            print("Huge pages set to %s" % f.read().strip())
        sys.exit()
    blocks = []
    size = opts.pages * os.sysconf("SC_PAGE_SIZE")
    for i in range(0, opts.blocks):
        b = PhysMem(size, huge=opts.huge, lock=(not opts.no_lock))
        print(b)
        for m in b.pa_range():
            print("  %s" % m)
        buf = b.buffer()
        buf[3] = b'x'
        blocks.append(b)
    for b in blocks:
        buf = b.buffer()
        assert buf[3] == b'x'
        if b.is_locked:
            b.unlock()
