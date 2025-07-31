#!/usr/bin/python3

"""
Show CMN mesh interconnect as ASCII art

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import textdiagram


from cmn_enum import *


class CMNDiagram(textdiagram.TextDiagram):
    """
    ASCII art for a topological CMN mesh layout.
    May be subclassed to overlay additional information.
    """
    def __init__(self, cmn, small=False, compact=False, update=True, decimal=False, xwidth=0, xheight=0):
        textdiagram.TextDiagram.__init__(self, width=80, height=20)
        self.C = cmn
        self.compact = compact
        self.small = small
        (self.xw, self.yw) = (21, 6) if small else (38, 10)
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
        return ox * self.xw + 6

    def Y(self, oy):
        return oy * self.yw + 4

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
        if len(xp.children) < xp.n_children:
            # We didn't discover all children
            xp_label += "?"
            xp_color = "red"
        return (xp_label, xp_color)

    def port_label_color(self, xp, p):
        devtype = xp.port_device_type(p)
        if devtype is None:
            return (None, None)
        dev_label = xp.port_device_type_str(p)
        if self.small:
            ix = dev_label.find('_')
            if ix > 0:
                dev_label = dev_label[:ix]
        dev_color = self.dev_type_color(dev_label)
        port_cal = xp.port_has_cal(p)
        if port_cal:
            dev_label = str(port_cal) + "x" + dev_label   # multiple devices on this port
            # TBD: handle HCALs
        dev_label = (self._id_fmt + ":%s") % (xp.port_base_id(p), dev_label)
        if xp.port_device_type_str(p).startswith("RN-F"):
            try:
                cpus = xp.port[p].cpus
                if cpus:
                    cpuns = sorted([co.cpu for co in cpus])
                    dev_label += ':' + ','.join([("#%u" % c) for c in cpuns])
            except AttributeError:
                pass     # probably cmn_devmem
        return (dev_label, dev_color)

    def node_label(self, n):
        s = (self._id_fmt + ":%s") % (n.node_id(), n.type_str())
        lid = n.logical_id()
        if lid is not None:
            s += str(lid)
        if n.is_external:
            s += "*"
        return s

    def extra_port_info(self, xp, p):
        subs = list(xp.port_nodes(p))
        subnames = [self.node_label(s) for s in subs]
        subnames = ','.join(subnames)
        return subnames

    def update(self):
        # draw vertical lines
        for x in range(0,self.C.dimX):
            for y in range(self.Y(0), self.Y(self.C.dimY-1)):
                self.at(self.X(x), y, '|')
        # draw horizontal lines
        for y in range(0,self.C.dimY):
            for x in range(self.X(0), self.X(self.C.dimX-1)):
                self.at(x, self.Y(y), '-')
        for xp in self.C.XPs():
            (cx, cy) = self.XP_xy(xp)
            (xp_label, xp_color) = self.xp_label_color(xp)
            self.at(cx, cy, xp_label, color=xp_color)
            for p in range(0, xp.n_device_ports()):
                (dev_label, dev_color) = self.port_label_color(xp, p)
                if dev_label is None:
                    continue
                if dev_color is not None:
                    if xp.port_device_type_str(p) == "HN-D":
                        # Does this have a DTC node, and if so, is it enabled?
                        for nd in xp.port_nodes(p):
                            if nd.type() == CMN_NODE_DT:
                                try:
                                    if nd.dtc_is_enabled():
                                        dev_color += "!"
                                except AttributeError:
                                    pass
                #(dx, dy) = self.port_dir(p)
                #pchar = "\\/"[dx == dy]
                if p == 0:
                    # lower left / SW
                    ea = -1
                    self.at(cx-1, cy-1, '/')
                    py = cy - 2
                    px = cx-2 if self.compact else cx-1-len(dev_label)
                elif p == 1:
                    # upper right / NE
                    ea = +1
                    px = cx + 2
                    py = cy + 2
                    self.at(cx+1, cy+1, '/')
                elif p == 2:
                    # lower right / SE
                    ea = -1
                    self.at(cx+1, cy-1, '\\')
                    px = cx + 2
                    py = cy-1 if self.compact else cy-2
                elif p == 3:
                    # upper left / NW
                    ea = +1
                    self.at(cx-1, cy+1, '\\')
                    if self.compact:
                        self.at(cx-2, cy+2, '\\')
                    px = cx-3 if self.compact else cx-2-len(dev_label)
                    py = cy+3 if self.compact else cy+2
                else:
                    assert False
                self.at(px, py, dev_label, color=dev_color)
                if not self.small:
                    extra_label = self.extra_port_info(xp, p)
                    self.at(px, py+ea, extra_label)
        return self


if __name__ == "__main__":
    import cmn_json
    import sys
    import argparse
    parser = argparse.ArgumentParser(description="CMN diagram")
    parser.add_argument("-i", "--input", type=str, default=cmn_json.cmn_config_filename(), help="CMN JSON")
    parser.add_argument("--cmn-instance", type=int, default=0, help="select CMN number")
    parser.add_argument("--small", action="store_true", help="smaller diagram")
    parser.add_argument("--large", action="store_true", help="more detailed diagram")
    parser.add_argument("--xwidth", type=int, default=0, help="width adjust +/-")
    parser.add_argument("--xheight", type=int, default=0, help="height adjust +/-")
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="color output")
    parser.add_argument("--test", action="store_true")
    opts = parser.parse_args()
    S = cmn_json.system_from_json_file(opts.input)
    C = S.CMNs[opts.cmn_instance]
    D = CMNDiagram(C, small=(not opts.large), xwidth=opts.xwidth, xheight=opts.xheight)
    D.update()
    print(D.str_color(no_color=(opts.color == "never"), force_color=(opts.color == "always"), for_file=sys.stdout), end="")
