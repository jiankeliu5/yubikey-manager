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

from __future__ import absolute_import, print_function

from PySide import QtCore
from .util import SignalMap
from ..device import open_device
from ..util import TRANSPORT


class Controller(QtCore.QObject):
    hasDeviceChanged = QtCore.Signal(bool)
    deviceNameChanged = QtCore.Signal(str)
    serialChanged = QtCore.Signal(int)
    capabilitiesChanged = QtCore.Signal(int)
    enabledChanged = QtCore.Signal(int)
    canModeSwitchChanged = QtCore.Signal(bool)

    def __init__(self, parent=None):
        super(Controller, self).__init__(parent)

        self._data = SignalMap()
        self._data.add_property('has_device', False, self.hasDeviceChanged)
        self._data.add_property('device_name', 'No YubiKey detected',
                                self.deviceNameChanged)
        self._data.add_property('serial', 0, self.serialChanged)
        self._data.add_property('capabilities', 0, self.capabilitiesChanged)
        self._data.add_property('enabled', 0, self.enabledChanged)
        self._data.add_property('can_mode_switch', False,
                                self.canModeSwitchChanged)

        self.refresh()

    @property
    def has_device(self):
        return self._data['has_device']

    @property
    def device_name(self):
        return self._data['device_name']

    @property
    def serial(self):
        return self._data['serial']

    @property
    def capabilities(self):
        return self._data['capabilities']

    @property
    def enabled(self):
        return self._data['enabled']

    @property
    def can_mode_switch(self):
        return self._data['can_mode_switch']

    def _grab_device(self, transports=sum(TRANSPORT)):
        if not self.has_device:
            raise ValueError('No device present')

        dev = open_device(transports)
        # TODO: Make sure same device.
        return dev

    def set_mode(self, mode):
        dev = self._grab_device()
        dev.mode = mode

    def refresh(self):
        had_device = self.has_device
        try:
            dev = open_device()
            if dev:
                self._data['has_device'] = True
                self._data['device_name'] = dev.device_name
                self._data['serial'] = dev.serial
                self._data['capabilities'] = dev.capabilities
                self._data['enabled'] = dev.enabled
                self._data['can_mode_switch'] = dev.can_mode_switch
            else:
                self._data.clear(False)
        except Exception as e:
            print("Couldn't open device: {:s}".format(e))
            self._data.clear(False)

        # If device was removed, we want to emit a signal for that alone.
        if had_device and not self.has_device:
            self.hasDeviceChanged.emit(False)