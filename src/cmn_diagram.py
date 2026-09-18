#!/usr/bin/python3

"""
Show CMN mesh interconnect as ASCII art

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import textdiagram


from cmn_enum import *


DEFAULT_RANGE = (0, 99)


class CMNDiagram(textdiagram.TextDiagram):
    """
    ASCII art for a topological CMN mesh layout.
    May be subclassed to overlay additional information.
    """
    def __init__(self, cmn, small=False, compact=False, update=True, decimal=False, xwidth=0, xheight=0, x_range=DEFAULT_RANGE, y_range=DEFAULT_RANGE):
        textdiagram.TextDiagram.__init__(self, width=80, height=20)
        self.C = cmn
        self.max_port = max([max([p.port_number for p in xp.ports()]) for xp in cmn.XPs()])
        self.compact = compact
        self.small = small
        def clip_range(r, d):
            (lo, hi) = r
            return (min(lo, d-1), min(hi, d-1))
        (self.x_lo, self.x_hi) = clip_range(x_range, self.C.dimX)
        (self.y_lo, self.y_hi) = clip_range(y_range, self.C.dimY)
        #print("effective range: x=%u..%u, y=%u..%u" % (self.x_lo, self.x_hi, self.y_lo, self.y_hi))
        (self.xw, self.yw) = (21, 6) if small else (38, 10)
        if self.max_port > 4:
            xheight += 2
        self.xw += xwidth
        self.yw += xheight
        self._id_fmt = "%u" if decimal else "%02x"
        if update:
            self.update()

    def port_dir(self, p):
        # Conventional orientation for rendering XP ports:
        #   3 1
        #   0 2
        return [(-1,-1), (1,1), (1,-1), (-1,1)][p]

    def dev_type_color(self, d):
        """
        Assign each device type a color for the diagram.
        """
        if d.startswith("RN-F"):
            return "cyan"        # CPUs and fully coherent requesters of any kind
        elif d.startswith("RN-"):
            return "yellow"       # other requesters e.g. RN-I
        elif d in ["HN-D", "HN-T", "HN-V"]:
            return "magenta"    # DVM nodes and debug nodes
        elif d.startswith("HN-F") or d.startswith("HN-S"):
            return "green"      # memory home nodes e.g. HN-F, SLC slices
        elif d.startswith("HN-"):
            return "yellow"     # I/O home nodes
        elif d.startswith("SN-"):
            return "red"
        else:
            return None

    def XP_xy(self, xp):
        (X, Y, P, D) = xp.coords()
        assert P == 0 and D == 0, "bad XP"
        cx = self.X(X)
        cy = self.Y(Y)
        return (cx, cy)

    def X(self, ox):
        assert ox >= 0 and ox < self.C.dimX, "bad X %u outside 0..%u" % (ox, self.C.dimX-1)
        return (ox - self.x_lo) * self.xw + 6

    def Y(self, oy):
        assert oy >= 0 and oy < self.C.dimY, "bad Y %u outside 0..%u" % (oy, self.C.dimY-1)
        return (oy - self.y_lo) * self.yw + 4

    def xp_label_color(self, xp):
        """
        For an XP, return (label text, label color) as a tuple.
        """
        xp_color = ""
        xp_label = self._id_fmt % xp.node_id()
        if True:
            (X, Y, P, D) = xp.coords()
            assert P == 0 and D == 0
            xp_label += "(%u,%u)" % (X,Y)
        if len(xp.children) < xp.n_children or xp.skipped_nodes:
            # We didn't discover all children
            xp_label += "?"
            xp_color = "red"
        if xp.is_disabled():
            xp_label += "!"
            xp_color = "red"
        return (xp_label, xp_color)

    def port_cpu_numbers(self, po):
        """CPU labels for this port; clients may supply their own annotations."""
        try:
            return sorted([co.cpu for co in po.cpus])
        except AttributeError:
            return []     # live ports do not have OS CPU mappings

    def port_label_color(self, po):
        if po is None:
            return (None, None)
        devtype = po.connected_type
        dev_label = cmn_port_device_type_str(devtype)
        if self.small:
            ix = dev_label.find('_')
            if ix > 0:
                dev_label = dev_label[:ix]
        dev_color = self.dev_type_color(dev_label)
        if po.cal:
            dev_label = str(po.cal) + "x" + dev_label   # multiple devices on this port
            # TBD: handle HCALs
        dev_label = (self._id_fmt + ":%s") % (po.base_id(), dev_label)
        if po.has_properties(CMN_PROP_RNF):
            cpuns = self.port_cpu_numbers(po)
            if cpuns:
                dev_label += ':' + ','.join([("#%u" % c) for c in cpuns])
        if any(n.is_disabled() for n in po.nodes(discover=False)):
            dev_label += "!"
            dev_color = "red"
        return (dev_label, dev_color)

    def node_label(self, n):
        s = (self._id_fmt + ":%s") % (n.node_id(), n.type_str())
        lid = n.logical_id()
        if lid is not None:
            s += str(lid)
        if n.is_external:
            s += "*"
        if n.is_disabled():
            s += "!"
        return s

    def extra_port_info(self, xp, p):
        subs = list(xp.port_nodes(p))
        subnames = [self.node_label(s) for s in subs]
        subnames = ','.join(subnames)
        return subnames

    def includes_xp(self, xp):
        (X, Y, P, D) = xp.coords()
        return (X >= self.x_lo and X <= self.x_hi) and (Y >= self.y_lo and Y <= self.y_hi)

    def XPs(self):
        for xp in self.C.XPs():
            if self.includes_xp(xp):
                yield xp

    def update(self):
        # draw vertical lines northwards
        for x in range(self.x_lo, self.x_hi+1):
            ylo = self.Y(self.y_lo)
            if self.y_lo > 0:
                ylo -= 4
            yhi = self.Y(self.y_hi)
            if self.y_hi < self.C.dimY - 1:
                yhi += 4
            for y in range(ylo, yhi):
                self.at(self.X(x), y, '|')
        # draw horizontal lines eastwards
        for y in range(self.y_lo, self.y_hi+1):
            xlo = self.X(self.x_lo)
            if self.x_lo > 0:
                xlo -= 6
            xhi = self.X(self.x_hi)
            if self.x_hi < self.C.dimX - 1:
                xhi += 10
            for x in range(xlo, xhi):
                self.at(x, self.Y(y), '-')
        # insert mesh credited slices
        for xp in self.XPs():
            if xp.x < self.C.dimX - 1:
                mcs = xp.mesh_credited_slices(0)
                if mcs:
                    self.at((self.X(xp.x) + self.X(xp.x+1)) // 2, self.Y(xp.y), str(mcs))
            if xp.y < self.C.dimY - 1:
                mcs = xp.mesh_credited_slices(1)
                if mcs:
                    self.at(self.X(xp.x), (self.Y(xp.y) + self.Y(xp.y+1)) // 2, str(mcs))
        for xp in self.XPs():
            (cx, cy) = self.XP_xy(xp)
            (xp_label, xp_color) = self.xp_label_color(xp)
            self.at(cx, cy, xp_label, color=xp_color)
            for po in xp.ports():
                p = po.port_number
                (dev_label, dev_color) = self.port_label_color(po)
                if dev_label is None:
                    continue
                #(dx, dy) = self.port_dir(p)
                #pchar = "\\/"[dx == dy]
                if p in [0, 4]:
                    # lower left / SW
                    ea = -1
                    self.at(cx-1, cy-1, '/')
                    py = cy - 2
                    px = cx-2 if self.compact else cx-1-len(dev_label)
                    if p == 4:
                        py -= 1
                elif p in [1, 5]:
                    # upper right / NE
                    ea = +1
                    px = cx + 2
                    py = cy + 2
                    if p == 5:
                        py += 1
                    self.at(cx+1, cy+1, '/')
                elif p in [2, 6]:
                    # lower right / SE
                    ea = -1
                    self.at(cx+1, cy-1, '\\')
                    px = cx + 2
                    py = cy-1 if self.compact else cy-2
                    if p == 6:
                        py -= 1
                elif p in [3, 7]:
                    # upper left / NW
                    ea = +1
                    self.at(cx-1, cy+1, '\\')
                    if self.compact:
                        self.at(cx-2, cy+2, '\\')
                    px = cx-3 if self.compact else cx-2-len(dev_label)
                    py = cy+3 if self.compact else cy+2
                    if p == 7:
                        py += 1
                else:
                    assert False
                self.at(px, py, dev_label, color=dev_color)
                if not self.small:
                    extra_label = self.extra_port_info(xp, p)
                    self.at(px, py+ea, extra_label)
        if any(xp.is_disabled() or any(n.is_disabled() for po in xp.ports()
                                      for n in po.nodes(discover=False)) for xp in self.XPs()):
            self.at(0, self.Y(self.y_hi)+6, "! disabled node (port: contains disabled nodes)")
        return self


def range_str(s):
    """
    Take a range string and return a tuple (min, max) inclusive.
    """
    t = s.split("..")
    if len(t) > 2:
        raise ValueError()
    if len(t) == 1:
        if not t[0]:
            return DEFAULT_RANGE
        return (int(t[0]), int(t[0]))
    lo = int(t[0]) if t[0] else 0
    hi = int(t[1]) if t[1] else DEFAULT_RANGE[1]
    return (lo, hi)


assert range_str("") == DEFAULT_RANGE
assert range_str("3") == (3, 3)
assert range_str("..3") == (0, 3)
assert range_str("1..5") == (1, 5)


def main(argv):
    import cmn_json
    import sys
    import argparse
    parser = argparse.ArgumentParser(description="CMN diagram")
    parser.add_argument("-i", "--input", type=str, default=cmn_json.cmn_config_filename(), help="CMN JSON")
    parser.add_argument("--cmn-instance", type=int, help="select CMN number")
    parser.add_argument("--small", action="store_true", help="smaller diagram")
    parser.add_argument("--large", action="store_true", help="more detailed diagram")
    parser.add_argument("--xwidth", type=int, default=0, help="width adjust +/-")
    parser.add_argument("--xheight", type=int, default=0, help="height adjust +/-")
    parser.add_argument("--x", type=range_str, default=DEFAULT_RANGE, help="X coordinate range")
    parser.add_argument("--y", type=range_str, default=DEFAULT_RANGE, help="Y coordinate range")
    parser.add_argument("--decimal", action="store_true", help="node ids in decimal")
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="color output")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("inputs", type=str, nargs="*", help="additional JSON inputs")
    opts = parser.parse_args(argv)
    if not opts.inputs:
        opts.inputs = [opts.input]
    for fn in opts.inputs:
        if len(opts.inputs) > 1:
            print("%s:" % fn)
        S = cmn_json.load_system_for_cli(fn)
        for C in S.cmn_instances(instance=opts.cmn_instance):
            print()
            print("%s:" % C)
            D = CMNDiagram(C, small=(not opts.large), decimal=opts.decimal, xwidth=opts.xwidth, xheight=opts.xheight, x_range=opts.x, y_range=opts.y)
            D.update()
            print(D.str_color(no_color=(opts.color == "never"), force_color=(opts.color == "always"), for_file=sys.stdout), end="")


if __name__ == "__main__":
    main(sys.argv[1:])
