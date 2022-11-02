#! /usr/bin/env python3
import fileinput
import itertools
import os
import sys
from subprocess import DEVNULL, run


params=[
"XMSSMT-SHA2_20/2_256",
"XMSSMT-SHA2_20/4_256",
"XMSSMT-SHA2_40/4_256",
"XMSSMT-SHA2_40/8_256",
"XMSSMT-SHA2_60/6_256",
"XMSSMT-SHA2_60/12_256",
"XMSSMT-SHA2_20/2_512",
"XMSSMT-SHA2_20/4_512",
"XMSSMT-SHA2_40/4_512",
"XMSSMT-SHA2_40/8_512",
"XMSSMT-SHA2_60/6_512",
"XMSSMT-SHA2_60/12_512",
"XMSSMT-SHA2_20/2_192",
"XMSSMT-SHA2_20/4_192",
"XMSSMT-SHA2_40/4_192",
"XMSSMT-SHA2_40/8_192",
"XMSSMT-SHA2_60/6_192",
"XMSSMT-SHA2_60/12_192",
"XMSSMT-SHAKE_20/2_256",
        "XMSSMT-SHAKE_20/4_256",
        "XMSSMT-SHAKE_40/4_256",
        "XMSSMT-SHAKE_40/8_256",
        "XMSSMT-SHAKE_60/6_256",
        "XMSSMT-SHAKE_60/12_256",
        "XMSSMT-SHAKE_20/4_512",
        "XMSSMT-SHAKE_40/4_512",
        "XMSSMT-SHAKE_40/8_512",
        "XMSSMT-SHAKE_60/6_512",
        "XMSSMT-SHAKE_60/12_512",
        "XMSSMT-SHAKE256_20/2_256",
        "XMSSMT-SHAKE256_20/4_256",
        "XMSSMT-SHAKE256_40/4_256",
        "XMSSMT-SHAKE256_40/8_256",
        "XMSSMT-SHAKE256_60/6_256",
        "XMSSMT-SHAKE256_60/12_256",
        "XMSSMT-SHAKE256_20/2_192",
        "XMSSMT-SHAKE256_20/4_192",
        "XMSSMT-SHAKE256_40/4_192",
        "XMSSMT-SHAKE256_40/8_192",
        "XMSSMT-SHAKE256_60/6_192",
        "XMSSMT-SHAKE256_60/12_192"]

for para in params:
    print("Benchmarking", para)
    p = 'PARAMS={}'.format(para)
    run(["make", "clean", p], stdout=DEVNULL, stderr=sys.stderr)
    run(["make", "test/speed.exec", p], stderr=sys.stderr)
    print(flush=True)

