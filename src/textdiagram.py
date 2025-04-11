#!/usr/bin/python333

"""
Simple ASCII art

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

Coordinates are the usual math orientation, i.e. (1,1) is north-east of (0,0).
"""

from __future__ import print_function

import os
import sys
import platform
import atexit     # if we hide the cursor, restore it on exit

RED      = 1
GREEN    = 2
YELLOW   = 3
BLUE     = 4    # generally too dark to read
MAGENTA  = 5
CYAN     = 6

_color_map = {
    "none": 0, "": 0, "white": 0,
    "red": 1,
    "green": 2,
    "yellow": 3,
    "blue": 4,
    "magenta": 5,
    "cyan": 6
}

_no_color = os.environ.get("NO_COLOR")

_ANSI_RESET = "\x1b[0m"

# Turn an integer into a printable character
_alphameric = " 123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _color_key(s):
    """
    Given a format string:
      <color>[*!]
    return a single printable character key to encode the color and format.
    Space means default color and format.

    Color can be specified either by name or by number.
    """
    is_intense = False
    is_inverted = False
    if s is None:
        return 0
    try:
        x = int(s)
    except ValueError:
        s = s.lower()
        while s and s[-1] in "*!":
            if s[-1] == "*":
                is_intense = True
            elif s[-1] == "!":
                is_inverted = True
            s = s[:-1]
        x = _color_map[s]
    if _no_color:
        x = 0
    if is_intense:
        x |= 8
    if is_inverted:
        x |= 16
    key = _alphameric[x]
    return key


def _key_ansi(c):
    """
    Given a format key, return the ANSI escape sequence.
    """
    code = _alphameric.index(c)    # by construction, it must be an alphameric character
    a = []
    if code & 8:
        code -= 8
        a.append("1")      # intense
    if code & 16:
        code -= 16
        if False:
            a.append("7")      # invert
            a.append("43")     # yellow, make text stand out more
            a.append("3" + str(code))
        else:
            a.append("4" + str(code))    # background color
    else:
        a.append("3" + str(code))
    return "\x1b[" + ";".join(a) + "m"


g_in_eclipse = None

def _in_eclipse():
    """
    Check if we're running under Eclipse. We only need to do this if we're
    in Jython, but this distinguishes Eclipse from e.g. Arm Debugger CLI.
    """
    global g_in_eclipse
    if g_in_eclipse is None:
        try:
            # Matt Sealey's suggestion for detecting Eclipse
            from org.eclipse.ui.console import AbstractConsole as __AC
            g_in_eclipse = True
        except ImportError:
            g_in_eclipse = False
    return g_in_eclipse


class TextDiagram():
    """
    ASCII art

    The diagram is maintained as an array of arrays of characters.
    A 'shadow' diagram (itself an instance of TextDiagram) may also be
    present containing formatting codes.
    """
    def __init__(self, width=80, height=10):
        # Width and height are, for the moment, ignored - instead the
        # diagram is expanded elastically
        self._hid_cursor = False
        self.minX = 0
        self.clear()

    def clear(self):
        self.lines = []
        self.colors = None

    def max_Y(self):
        return len(self.lines)

    def at(self, x, y, s, color=None):
        """
        Put a text string at the selected coordinates.
        """
        if x < self.minX:
            adj = self.minX - x
            spc = " " * adj
            for i in range(len(self.lines)):
                self.lines[i] = spc + self.lines[i]
            self.minX = x
        x -= self.minX
        if y >= len(self.lines):
            for i in range(len(self.lines), y+1):
                self.lines.append("")
        ln = self.lines[y]
        if len(ln) < x:
            ln += " " * (x-len(ln))
        self.lines[y] = ln[:x] + s + ln[x+len(s):]
        if color is not None:
            if self.colors is None:
                # Create a color map - which is itself a (monochrome) diagram
                self.colors = TextDiagram()
            self.colors.at(x, y, (_color_key(color) * len(s)))
        elif self.colors is not None:
            # make sure any previous color at this position doesn't persist
            self.colors.at(x, y, " "*len(s))
        return self

    def peek(self, x, y):
        """
        Get the character at a given position.
        """
        x -= self.minX
        if y >= len(self.lines):
            return " "
        if x >= len(self.lines[y]):
            return " "
        return self.lines[y][x]

    def cursor_up(self):
        """
        Return a string that, after printing the diagram, repositions the cursor to
        redraw it.
        """
        return "\x1b[%uA" % self.max_Y()

    def str_mono(self):
        """
        Return the entire diagram as a multi-line string suitable for printing.
        """
        return '\n'.join(reversed(self.lines)) + '\n'

    def str_color(self, for_file=None, no_color=False, force_color=False, restore=False):
        """
        Return the entire diagram as a multi-line string suitable for printing,
        on output that might understand ANSI escape codes.

          no_color=True      - disable ANSI escape codes
          force_color=True   - forces ANSI escape codes even if output is non-tty
        """
        with_colors = True
        if self.colors is None:
            # No color annotations have yet been defined for this diagram
            with_colors = False
        elif no_color:
            with_colors = False
        elif force_color:
            with_colors = True
        elif for_file is not None:
            if platform.python_implementation() != "Jython":
                with_colors = os.isatty(for_file.fileno())
            else:
                # os.isatty() might work, but return False for stdout
                with_colors == (for_file == sys.stdout and not _in_eclipse())
        if not with_colors:
            s = self.str_mono()
        else:
            s = ""
            for (yy, ln) in enumerate(reversed(self.lines)):
                y = self.max_Y() - 1 - yy
                ccol = " "
                for (x, c) in enumerate(ln):
                    col = self.colors.peek(x, y)
                    if col != ccol:
                        if ccol != " ":
                            s += _ANSI_RESET
                        if col != " ":
                            s += _key_ansi(col)
                        ccol = col
                    s += c
                if ccol != " ":
                    s += _ANSI_RESET
                s += "\n"
        if restore:
            s += self.cursor_up()
        return s

    def hide_cursor(self):
        hide_cursor()
        self._hid_cursor = True

    def show_cursor(self):
        show_cursor()
        self._hid_cursor = False

    def __del__(self):
        if self._hid_cursor:
            self.show_cursor()

    def __str__(self):
        return self.str_mono()


def show_cursor(file=None):
    if file is None:
        file = sys.stdout
    print("\x1b[?25h", end="", file=file)


def hide_cursor(file=None):
    if file is None:
        file = sys.stdout
    print("\x1b[?25l", end="", file=file)
    atexit.register(show_cursor, file)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ASCII art diagram")
    parser.add_argument("--color", type=str)
    opts = parser.parse_args()
    cs = ""
    for col in _color_map.keys():
        for suf in ["","!","*","*!"]:
            st = col + suf
            cs += _key_ansi(_color_key(st)) + st + _ANSI_RESET
    print(cs)
    D = TextDiagram()
    D.at(10,10,"center",color=opts.color)
    D.at(10,20,"N",color=1)
    D.at(17,17,"NE",color=2)
    D.at(20,10,"E",color=3)
    D.at(17,3,"SE",color="BLUE")
    D.at(0,10,"W",color=5)
    D.at(3,17,"NW",color=6)
    D.at(10,0,"S",color=7)
    D.at(3,3,"SW",color=8)
    print(D.str_color(for_file=sys.stdout))
