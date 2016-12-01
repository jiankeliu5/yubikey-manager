#!/usr/bin/env python

from ykman.descriptor import get_descriptors
from binascii import a2b_hex, b2a_hex
from ykman.native.ykpiv import ykpiv, ykpiv_state
from ctypes import *

_YKPIV_MIN_VERSION = b'1.5.0'

libversion = ykpiv.ykpiv_check_version(_YKPIV_MIN_VERSION)
if not libversion:
    raise Exception('libykpiv >= %s required, got %s' % (
        _YKPIV_MIN_VERSION, ykpiv.ykpiv_check_version(None)))

state = POINTER(ykpiv_state)()
print('ykpiv_init: ', ykpiv.ykpiv_init(byref(state), 0))

d = next(get_descriptors())

dev = d.open_device()

dr = dev.driver

hcontext = dr._conn.component.hcontext
hcard = dr._conn.component.hcard

ykpiv.ykpiv_connect2(state, hcontext, hcard)

buf = (c_ubyte * 4096)()
buf_len = c_size_t(sizeof(buf))

ykpiv.ykpiv_fetch_object(state, 0x5fc102, buf, byref(buf_len))

data = bytes(buf[:buf_len.value])
print('CHUID:', b2a_hex(data))
