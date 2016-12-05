# Copyright (c) 2015 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


from ykman.native.ykpiv import ykpiv, ykpiv_state, YKPIV
from ykman.yubicommon.compat import int2byte
from ykman.driver_ccid import APDUError
from ykman.util import tlv
from ctypes import (POINTER, byref, sizeof, create_string_buffer, c_ubyte,
                    c_size_t, c_int)
import struct


_YKPIV_MIN_VERSION = b'1.5.0'
ykpiv_version = ykpiv.ykpiv_check_version(None)


class YkpivError(Exception):
    """Thrown if a ykpiv call fails."""

    def __init__(self, errno):
        self.errno = errno
        self.message = ykpiv.ykpiv_strerror(errno)

    def __str__(self):
        return 'ykpers error {}, {}'.format(self.errno, self.message)


def check(errno):
    if errno != 0:
        raise YkpivError(errno)


def _init_state(driver):
    state = POINTER(ykpiv_state)()
    check(ykpiv.ykpiv_init(byref(state), 0))  # TODO: Enable setting debug
    scard_component = driver._conn.component
    hcontext = scard_component.hcontext
    hcard = scard_component.hcard

    check(ykpiv.ykpiv_connect2(state, hcontext, hcard))
    return state


class PivController(object):

    def __init__(self, driver):
        self._driver = driver
        if not ykpiv.ykpiv_check_version(_YKPIV_MIN_VERSION):
            raise Exception('libykpiv >= %s required' % _YKPIV_MIN_VERSION)
        self._state = _init_state(driver)
        self._version = self._read_version()
        self._chuid = self._read_chuid()

    @property
    def version(self):
        return self._version

    @property
    def chuid(self):
        return self._chuid

    def _read_version(self):
        v = create_string_buffer(10)
        check(ykpiv.ykpiv_get_version(self._state, v, sizeof(v)))
        return tuple(int(d) for d in v.value.decode('ascii').split('.'))

    def _read_chuid(self):
        try:
            return self.fetch_object(YKPIV.OBJ.CHUID)
        except YkpivError:  # No chuid set?
            return None

    def fetch_object(self, object_id):
        buf = (c_ubyte * 4096)()
        buf_len = c_size_t(sizeof(buf))

        check(ykpiv.ykpiv_fetch_object(self._state, object_id, buf,
                                       byref(buf_len)))
        return b''.join(int2byte(b) for b in buf[:buf_len.value])

    def transfer_data(self, ins, data=None, p1=0, p2=0):
        if data is not None:
            data = (c_ubyte * len(data)).from_buffer_copy(data)
        sw = c_int(0)
        buf = (c_ubyte * 4096)()
        buf_len = c_size_t(sizeof(buf))
        templ = (c_ubyte * 4).from_buffer_copy(
            struct.pack('<4b', 0, ins, p1, p2))
        check(ykpiv.ykpiv_transfer_data(self._state, templ, data, len(data),
                                        buf, byref(buf_len), byref(sw)))

        resp = b''.join(int2byte(b) for b in buf[:buf_len.value])
        if sw.value != YKPIV.SW.SUCCESS:
            raise APDUError(resp, sw.value)
        return data

    def reset(self):
        self.transfer_data(YKPIV.INS.RESET)

    def generate_key(self, slot, algorithm, pin_policy, touch_policy):
        data = tlv(0xac, tlv(0x80, int2byte(algorithm)))
        if pin_policy != YKPIV.PINPOLICY.DEFAULT:
            data += tlv(0xaa, int2byte(pin_policy))
        if touch_policy != YKPIV.TOUCHPOLICY.DEFAULT:
            data += tlv(0xab, int2byte(touch_policy))

        return self.transfer_data(YKPIV.INS.GENERATE_ASYMMETRIC, data, p2=slot)
