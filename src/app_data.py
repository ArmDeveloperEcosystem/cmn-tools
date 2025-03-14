#!/usr/bin/python

"""
Manage a cache of application data, in a portable way.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

Works in the following situations:

  - Linux
  - Linux as sudo
  - Windows
  - Jython under Linux
  - Jython under Windows
"""

from __future__ import print_function


import os
import sys


o_dry_run = False


def home_dir():
    """
    Linux: get the current (real) user's home directory, even if sudo.
    Some versions of sudo override HOME to point to /root, so don't use that.
    """
    user = os.environ.get("SUDO_USER", os.environ.get("USER"))
    return os.path.expanduser("~" + user)


def app_data_cache(fn=None, app="arm"):
    """
    Get the default location for application cached data,
    ensuring that the subdirectory exists.
    We allow for situation where this script is run under "sudo"
    but we want to avoid files being created with owner as root.
    """
    if "LOCALAPPDATA" in os.environ:
        # Windows, or Jython-under-Windows
        pcache = os.environ["LOCALAPPDATA"]
    else:
        pcache = os.path.join(home_dir(), ".cache")
        ensure_directory_exists(pcache)
    if app is not None:
        pcache = os.path.join(pcache, app)
        ensure_directory_exists(pcache)
    if fn is not None:
        return os.path.join(pcache, fn)
    return pcache


def ensure_directory_exists(dir):
    """
    Ensure a directory exists, creating it (as non-root) if not.
    Will likely throw an error if the path exists as a file.
    """
    if not os.path.isdir(dir) and not o_dry_run:
        os.mkdir(dir)
        change_to_real_user_if_sudo(dir)
    return dir


def change_to_real_user_if_sudo(fn):
    """
    When writing a file as sudo, we might want it to be owned by the "real" user
    to avoid complications when later using it as non-sudo.
    """
    if "SUDO_USER" in os.environ:
        user = os.environ["SUDO_USER"]
        if sys.version_info[0] >= 3:
            import shutil
            shutil.chown(fn, user=user, group=user)
        else:
            # Python2 shutil doesn't have chown().
            import pwd
            import grp
            os.chown(fn, pwd.getpwnam(user).pw_uid, grp.getgrnam(user).gr_gid)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="test app datacache")
    parser.add_argument("--create", action="store_true", help="create dirs if necessary")
    parser.add_argument("--app", default="arm", type=str, help="application/organization")
    parser.add_argument("--name", default="appdatatest", type=str)
    opts = parser.parse_args()
    o_dry_run = not opts.create
    fn = app_data_cache(opts.name, app=opts.app)
    print("file: %s" % fn)
    print("directory exists: %s" % os.path.isdir(os.path.dirname(fn)))
