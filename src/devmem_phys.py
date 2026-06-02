#!/usr/bin/python

"""
Physical memory access via a separate executable.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0

Read and write commands are piped into the executable.
"""

from __future__ import print_function


import sys
import os
import subprocess


ENV_MEMACCESS = "CMN_MEMACCESS"

DEFAULT_COMMAND = "./cmd-mem"


def memory_interface_available():
    return ENV_MEMACCESS in os.environ


class MemoryInterface:
    """
    Wrap an external command which provides a physical memory interface.
    The external command persists, and is accessed via input and output pipes
    (similar to how "addr2line" is sometimes used).
    """
    def __init__(self, command=None, verbose=0):
        self.verbose = verbose
        self.cmd = command or os.environ.get(ENV_MEMACCESS, DEFAULT_COMMAND)
        if verbose > 0:
            self.cmd += " -%s" % ("v" * verbose)
        self.cur_n_bytes = None
        self.p = None
        self.p = subprocess.Popen(self.cmd.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        if self.verbose:
            print("%s started..." % self.cmd)

    def __del__(self):
        if self.p is not None:
            self.pipe_expect_ok("close")
            self.p.terminate()

    def pipe_in(self, s):
        if self.verbose:
            print("--> %s" % s)
        self.p.stdin.write(s.encode() + b"\n")
        self.p.stdin.flush()

    def pipe_out(self):
        if self.verbose >= 2:
            print("--- waiting...")
        s = self.p.stdout.readline().decode().strip()
        if self.verbose:
            print("<-- %s" % s)
        return s

    def pipe(self, s):
        self.pipe_in(s)
        return self.pipe_out()

    def pipe_expect_ok(self, s):
        rs = self.pipe(s)
        if rs != "ok":
            print("expected 'ok': %s" % (rs), file=sys.stderr)

    def ensure_n_bytes(self, n_bytes):
        if self.cur_n_bytes != n_bytes:
            self.pipe_expect_ok("size %u" % n_bytes)
            self.cur_n_bytes = n_bytes

    def read(self, addr, n_bytes):
        self.ensure_n_bytes(n_bytes)
        s = self.pipe("read 0x%x" % addr)
        return int(s, 16)

    def write(self, addr, n_bytes, value):
        self.ensure_n_bytes(n_bytes)
        self.pipe_expect_ok("write 0x%x 0x%x" % (addr, value))


def main(argv):
    """
    Command-line interface is just for testing
    """
    import argparse
    parser = argparse.ArgumentParser(description="Physical memory access (test)")
    parser.add_argument("--command", type=str, help="redirector command")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("cmds", nargs="*", help="test commands to execute")
    opts = parser.parse_args()
    M = MemoryInterface(command=opts.command, verbose=opts.verbose)
    for c in opts.cmds:
        if c.startswith("r"):
            addr = int(c[1:], 16)
            print("read 0x%x => 0x%x" % (addr, M.read64(addr)))
        elif c.startswith("w"):
            (addr, value) = c.split('=')
            addr = int(addr[1:], 16)
            value = int(value, 16)
            print("write 0x%x := 0x%x" % (addr, value))
            M.write64(addr, value)
        elif c == "nop":
            M.pipe_expect_ok("nop")
        else:
            print("bad command '%s', expected 'r<addr>', 'w<addr>=<value>'", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
