This directory contains CMN register definitions, in a simple
text-based format, read by cmn_regdump.py.

Two versions of each file are supplied, with and without textual
descriptions for registers and fields.

Register offsets and field offsets differ not only between products
(CMN-600, CMN-700 etc.), but between major revisions (the 'r' in 'rxpx')
of the same product.

The definition files are shipped uncompressed, but cmn_regdump.py
can read them when compressed with gzip - to save space, just do
"gzip *" in this directory.
