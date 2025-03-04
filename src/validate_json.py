#!/usr/bin/python

"""
Validate files according to their JSON schema.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import os
import sys
import json
import re

# try "sudo pip install jsonschema" if this doesn't work
import jsonschema


n_failed = 0
o_max_errors = 1

o_verbose = 0


def fix_trailing(s):
    s = re.sub(r',(\s*[}\]])', r'\1', s)
    return s


assert fix_trailing("[{ 'a', 'b',\n },]") == "[{ 'a', 'b'\n }]"


class Schema:
    """
    A JSON schema, with validator
    """
    def __init__(self, fn, fix_trailing_comma=False):
        assert fn.endswith(".json"), "bad JSON schema name (expected .json): %s" % fn
        with open(fn) as f:
            schema = json.load(f)
        # Strictly speaking, a JSON schema doesn't have to have a "$schema" property,
        # but we assume all ours do.
        assert "$schema" in schema, "%s: doesn't look like a JSON schema" % fn
        self.schema = schema
        self.validator = jsonschema.Draft4Validator(schema)

    def name(self):
        return self.schema["title"]

    def __str__(self):
        return self.name()

    def fail(self, s):
        global n_failed
        print("** %s" % (s), file=sys.stderr)
        n_failed += 1
        if n_failed >= o_max_errors:
            sys.exit(1)

    def validate_json(self, j):
        self.validator.validate(j)

    def validate_file(self, fn):
        global n_failed
        print("Validating as %s: %s..." % (self.name(), fn))
        assert fn.endswith(".json"), "bad data file name (expected .json): %s" % fn
        with open(fn) as f:
            try:
                if not opts.fix_trailing_comma:
                    j = json.load(f)
                else:
                    # Hack for Linux PMU files which have trailing commas.
                    # Delete comma from all occurrences of comma+whitespace+] or comma+whitespace+}.
                    # Might affect string texts, but this should not affect validation.
                    text = f.read()
                    text = fix_trailing(text)
                    #text = text.strip() + "\n"
                    #assert text.endswith("},\n]\n") or text.endswith("}\n]\n"), "%s: unexpected: %s" % (fn, text[-10:])
                    #if text.endswith("},\n]\n"):
                    #    text = text[:-4] + text[-3:]
                    j = json.loads(text)
            except json.decoder.JSONDecodeError as e:
                self.fail("%s: failed to load JSON: %s" % (fn, e))
                return
        #self.validate_json(j)
        try:
            self.validate_json(j)
        except jsonschema.exceptions.ValidationError as e:
            self.fail("%s: failed '%s': %s" % (fn, self.name(), str(e)[:400]))


def validate_files(val, dir):
    if os.path.isfile(dir):
        val.validate_file(dir)
        return
    for root, dirs, files in os.walk(dir):
        for h in files:
            if h.endswith(".json") and not h.endswith("schema.json"):
                val.validate_file(os.path.join(root, h))


# It would be nice if the PMU definition files could indicate their schema,
# so that we know we're actually checking PMU definition files and not some
# unrelated JSON files...
# See https://github.com/json-schema/json-schema/issues/220


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="validate JSON files against a schema")
    parser.add_argument("--schema", type=str, required=True, help="JSON schema")
    parser.add_argument("--fix-trailing-comma", action="store_true", help="allow trailing comma in top-level array")
    parser.add_argument("--max-errors", type=int, default=999, help="max number of errors")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("dirs", nargs="*", help="directories with JSON files to validate")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    o_max_errors = opts.max_errors
    validator = Schema(opts.schema, fix_trailing_comma=opts.fix_trailing_comma)
    for d in opts.dirs:
        validate_files(validator, d)
    sys.exit(n_failed > 0)
