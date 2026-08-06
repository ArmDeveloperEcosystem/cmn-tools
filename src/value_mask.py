#!/usr/bin/python3

"""
Helpers for value/don't-care mask conversion.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


class ValueMask(object):
    """
    A value plus a don't-care mask.

    Mask bits set to 1 indicate don't-care positions. This is the object form
    returned by convert_value(); use as_tuple() when older value/mask tuple
    handling is needed.
    """
    def __init__(self, value, mask=0):
        self.value = value
        self.mask = mask

    def as_tuple(self):
        """
        Return this value/mask pair as (value, mask).
        """
        return (self.value, self.mask)

    def __iter__(self):
        return iter(self.as_tuple())

    def __str__(self):
        return str(unconvert_value_mask(self.value, self.mask))

    def __repr__(self):
        return "ValueMask(%s, %s)" % (self.value, self.mask)


def convert_value(v):
    """
    Convert a numeric or masked-numeric value specifier to a ValueMask object.

    The returned mask uses 1 bits for don't-care positions. A value specifier
    may be an integer, a string accepted by int(v, 0), or a wildcard string:
      0b1x00    -> ValueMask(0x8, 0x4)
      0x4xxx    -> ValueMask(0x4000, 0x0fff)

    Table lookup for enumerated values is expected to happen before calling
    this function. Invalid input raises ValueError.
    """
    if isinstance(v, bool):
        return ValueMask(int(v), 0)
    if isinstance(v, int):
        return ValueMask(v, 0)
    try:
        v = int(v, 0)
        return ValueMask(v, 0)
    except Exception:
        pass
    try:
        if v.startswith("0b"):
            v0 = int(v.replace('x', '0'), 2)
            v1 = int(v.replace('x', '1'), 2)
            return ValueMask(v0, v1-v0)
        if v.startswith("0x"):
            v0 = int(v[2:].replace('x', '0'), 16)
            v1 = int(v[2:].replace('x', 'f'), 16)
            return ValueMask(v0, v1-v0)
    except AttributeError:
        pass
    raise ValueError("expected integer or bitmask")


def unconvert_value_mask(v, m):
    """
    Convert a value/don't-care mask pair back to an integer or wildcard string.
    """
    if m == 0:
        return v
    s = ""
    while m or v:
        if m & 1:
            s = "x" + s
        else:
            s = str(v & 1) + s
        v >>= 1
        m >>= 1
    return "0b" + s


assert convert_value(123).as_tuple() == (123, 0)
assert convert_value("123").as_tuple() == (123, 0)
assert convert_value("0x123").as_tuple() == (0x123, 0)
assert convert_value("0bx1xx").as_tuple() == (4, 0b1011)

assert str(convert_value(123)) == "123"
assert str(convert_value("0bx1xx")) == "0bx1xx"
assert unconvert_value_mask(123, 0) == 123
assert unconvert_value_mask(4, 0b1011) == "0bx1xx"
