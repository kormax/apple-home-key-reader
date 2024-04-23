# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
# This file is a direct modification of https://github.com/nfcpy/nfcpy/blob/master/src/nfc/clf/__init__.py and thus inherits its license
# Modifications are targeted towards adding "Broadcast" frames functionality
# Parts of the code that were changed are denoted by "Modified code BEGIN" and "Modified code END" comments


import ast
import errno
import inspect
import logging
import os
import platform
import re
import time
from binascii import hexlify

import nfc.clf.pn53x
import usb
from nfc.clf import (
    CommunicationError,
    ContactlessFrontend,
    ProtocolError,
    RemoteTarget,
    UnsupportedTargetError,
)
from nfc.tag import activate
from nfc.tag.tt4 import Type4Tag

from util.generic import chunked
# Modified code BEGIN
from util.nfc import with_crc16a


# Monkey patch pn532 init function to disable baudrate renegotiation
def patch_pn532_init_function():
    """This function modifies code of pn532 init function to prevent baudrate renegotiation on Linux systems"""
    import nfc.clf.pn532 as pn532_module

    class ModifyBaudrateVisitor(ast.NodeTransformer):
        def visit_Assign(self, node):
            if isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'change_baudrate':
                node.value = ast.parse("False").body[0].value
            return node

    init_src = inspect.getsource(pn532_module.init)
    init_ast = ast.parse(init_src)
    modified_tree = ModifyBaudrateVisitor().visit(init_ast)
    # Convert the modified AST object back to code
    modified_code = compile(modified_tree, filename='', mode='exec')
    exec(modified_code, vars(pn532_module))


def patch_usb_transport_implementation():
    DIRECTION_MASK = 0b1_0000000
    DIRECTION_OUT = 0b0_0000000
    DIRECTION_IN = 0b1_0000000

    TRANSFER_MASK = 0b000000_11
    TRANSFER_BULK = 0b000000_10

    def _find_endpoint(device, endpoint_rule=lambda e: True):
        for configuration in device.configurations():
            for interface in configuration.interfaces():
                for endpoint in interface.endpoints():
                    if endpoint_rule(endpoint):
                        return configuration, interface, endpoint
        return None, None, None

    def is_unix_based():
        return platform.system() in ("Linux", "Darwin")

    class USB(object):
        TYPE = "USB"

        @classmethod
        def find(cls, path):
            if not path.startswith("usb"):
                return

            usb_or_none = re.compile(r'^(usb|)$')
            usb_vid_pid = re.compile(r'^usb(:[0-9a-fA-F]{4})(:[0-9a-fA-F]{4})?$')
            usb_bus_dev = re.compile(r'^usb(:[0-9]{1,3})(:[0-9]{1,3})?$')
            match = None

            for regex in (usb_vid_pid, usb_bus_dev, usb_or_none):
                m = regex.match(path)
                if m is not None:
                    log.debug("path matches {0!r}".format(regex.pattern))
                    if regex is usb_vid_pid:
                        match = [int(s.strip(':'), 16) for s in m.groups() if s]
                        match = dict(zip(['vid', 'pid'], match))
                    if regex is usb_bus_dev:
                        match = [int(s.strip(':'), 10) for s in m.groups() if s]
                        match = dict(zip(['bus', 'adr'], match))
                    if regex is usb_or_none:
                        match = dict()
                    break
            else:
                return None

            params = {
                k: v
                for k, v in {
                    "idVendor": match.get('vid'),
                    "idProduct": match.get('pid'),
                    "bus": match.get('bus'),
                    "address": match.get('address')
                }.items()
                if v is not None
            }

            devices = usb.core.find(
                **params,
                find_all=True
            )

            return [(d.idVendor, d.idProduct, d.bus, d.address) for d in devices]

        def __init__(self, usb_bus, dev_adr):
            self.kernel_driver_detached = False
            self.usb_dev = None
            self.usb_inp = None
            self.usb_out = None

            self.open(usb_bus, dev_adr)

        def __del__(self):
            self.close()

        def open(self, usb_bus, dev_adr):
            self.usb_dev = None
            self.usb_out = None
            self.usb_inp = None

            device = usb.core.find(
                bus=usb_bus,
                address=dev_adr,
            )
            if device is None:
                log.error("no device {0} on bus {1}".format(dev_adr, usb_bus))
                raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

            r_configuration, r_interface, read_endpoint = _find_endpoint(
                device,
                lambda e: (e.bEndpointAddress & DIRECTION_MASK) == DIRECTION_IN
                          and (e.bmAttributes & TRANSFER_MASK) == TRANSFER_BULK
            )

            w_configuration, w_interface, write_endpoint = _find_endpoint(
                device,
                lambda e: (e.bEndpointAddress & DIRECTION_MASK) == DIRECTION_OUT
                          and (e.bmAttributes & TRANSFER_MASK) == TRANSFER_BULK
            )
            if None in (r_configuration, r_interface, read_endpoint, w_configuration, w_interface, write_endpoint):
                log.error("no usb configuration settings, please replug device")
                raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

            self.usb_inp = read_endpoint
            self.usb_out = write_endpoint
            self.usb_dev = device

            logging.debug(f"{self.usb_dev=} {self.usb_inp=} {self.usb_out=}")

            if not (self.usb_inp and self.usb_out):
                log.error("no bulk endpoints for read and write")
                raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

            try:
                # workaround the PN533's buggy USB implementation
                self._manufacturer_name = self.usb_dev.manufacturer
                self._product_name = self.usb_dev.product
            except Exception:
                self._manufacturer_name = None
                self._product_name = None

            if is_unix_based() and self.usb_dev.is_kernel_driver_active(0):
                self.usb_dev.detach_kernel_driver(0)
                self.kernel_driver_detached = True
            usb.util.claim_interface(self.usb_dev, 0)

        def close(self):
            usb.util.release_interface(self.usb_dev, 0)
            if self.kernel_driver_detached:
                self.usb_dev.attach_kernel_driver(0)
            self.usb_dev = None
            self.usb_inp = None
            self.usb_out = None

        @property
        def manufacturer_name(self):
            return self._manufacturer_name

        @property
        def product_name(self):
            return self._product_name

        def read(self, timeout=0):
            if self.usb_inp is None:
                return

            try:
                frame = bytes(self.usb_inp.read(300, timeout=int(timeout * 1.25)))
            except usb.core.USBTimeoutError:
                raise IOError(errno.ETIMEDOUT, os.strerror(errno.ETIMEDOUT))
            except usb.core.USBError as error:
                log.error("%r", error)
                raise IOError(errno.EIO, os.strerror(errno.EIO))

            if len(frame) == 0:
                log.error("bulk read returned zero data")
                raise IOError(errno.EIO, os.strerror(errno.EIO))

            log.log(logging.DEBUG - 1, "<<< %s", hexlify(frame).decode())
            return frame

        def write(self, frame, timeout=0):
            if self.usb_out is None:
                return

            log.log(logging.DEBUG - 1, ">>> %s", hexlify(frame).decode())
            try:
                # Any message > wMaxPacketSize causes some ACR122U USB subsystem to crash
                # as seemingly for some reason, lower levels do not chunk the message properly at all times
                for chunk in chunked(frame, self.usb_out.wMaxPacketSize):
                    self.usb_out.write(data=bytes(chunk), timeout=timeout)
                # USB detects end of a message when a packet sent had length < wMaxPacketSize
                # If a last packet just so happens to be of size == wMaxPacketSize, we have to send an empty packet
                # to notify the device about the end of transmission
                if len(frame) % self.usb_out.wMaxPacketSize == 0:
                    self.usb_out.write(data=b'', timeout=timeout)
            except usb.core.USBTimeoutError:
                raise IOError(errno.ETIMEDOUT, os.strerror(errno.ETIMEDOUT))
            except usb.core.USBError as error:
                log.error("%r", error)
                raise IOError(errno.EIO, os.strerror(errno.EIO))

    import nfc.clf.transport as transport

    transport.USB = USB


patch_pn532_init_function()
patch_usb_transport_implementation()

log = logging.getLogger(__name__)

# Re-declaring just for cleaner imports elsewhere
ISODEPTag = Type4Tag
RemoteTarget = RemoteTarget
activate = activate


# Modified code END


class BroadcastFrameContactlessFrontend(ContactlessFrontend):
    # Modified code BEGIN
    def __init__(self, path=None, *, broadcast_enabled=False):
        self.path = path
        self.broadcast_enabled = broadcast_enabled
        # We send None so that we can try activating the reader later in a loop instead of throwing an exception right away
        super().__init__(None)

    # Modified code END

    def sense(self, *targets, **options):
        def sense_tta(target):
            if target.sel_req and len(target.sel_req) not in (4, 7, 10):
                raise ValueError("sel_req must be 4, 7, or 10 byte")
            target = self.device.sense_tta(target)
            # log.debug("found %s", target)
            if target and len(target.sens_res) != 2:
                error = "SENS Response Format Error (wrong length)"
                log.debug(error)
                raise ProtocolError(error)
            if target and target.sens_res[0] & 0b00011111 == 0:
                if target.sens_res[1] & 0b00001111 != 0b1100:
                    error = "SENS Response Data Error (T1T config)"
                    log.debug(error)
                    raise ProtocolError(error)
                if not target.rid_res:
                    error = "RID Response Error (no response received)"
                    log.debug(error)
                    raise ProtocolError(error)
                if len(target.rid_res) != 6:
                    error = "RID Response Format Error (wrong length)"
                    log.debug(error)
                    raise ProtocolError(error)
                if target.rid_res[0] >> 4 != 0b0001:
                    error = "RID Response Data Error (invalid HR0)"
                    log.debug(error)
                    raise ProtocolError(error)
            return target

        def sense_ttb(target):
            return self.device.sense_ttb(target)

        def sense_ttf(target):
            return self.device.sense_ttf(target)

        def sense_dep(target):
            if len(target.atr_req) < 16:
                raise ValueError("minimum atr_req length is 16 byte")
            if len(target.atr_req) > 64:
                raise ValueError("maximum atr_req length is 64 byte")
            return self.device.sense_dep(target)

        # Modified code BEGIN
        def sense_broadcast(target, broadcast):
            # Correct implementation would be to define and call sense_broadcast from device implementation
            # and adding all support checks there. For simplicity, everything has been included in one file here
            if not self.broadcast_enabled:
                return

            if broadcast is None or len(broadcast) <= 0:
                # Skip broadcast if nothing to broadcast
                return

            if not any(target.brty.endswith(m) for m in ("A", "B")):
                # Skip broadcast for any NFC type that's not A or B
                return

            if not isinstance(self.device.chipset, nfc.clf.pn53x.Chipset):
                raise UnsupportedTargetError(
                    f"Broadcast frames are not supported with chipset {self.device} for target {target}"
                )

            # Turn off detection retries at it might break broadcast frame sequence
            self.device.chipset.rf_configuration(0x05, [0xFF, 0x01, 0x00])
            # Set a 12 ms response timeout. Normally, WUPA takes 1.6-4.4 ms, so this timeout is more than sufficient
            self.device.chipset.rf_configuration(0x02, [0x0A, 0x0B, 0x08])

            if target.brty.endswith("A"):
                self.device.chipset.write_register("CIU_BitFraming", 0x00)
                broadcast = with_crc16a(broadcast)
            try:
                _ = self.device.chipset.in_communicate_thru(broadcast, timeout=0.25)

                # Can proccess response here later
            except (nfc.clf.pn53x.Chipset.Error,) as e:
                # Timeout is OK for broadcast frames as we don't always expect an answer
                if e.errno != 0x01:
                    raise

        # Modified code END

        for target in targets:
            if not isinstance(target, RemoteTarget):
                raise ValueError("invalid target argument type: %r" % target)

        with self.lock:
            if self.device is None:
                raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

            self.target = None  # forget captured target
            self.device.mute()  # deactivate the rf field

            for i in range(max(1, options.get("iterations", 1))):
                started = time.time()
                for target in targets:
                    # log.debug("sense {0}".format(target))
                    try:
                        if target.atr_req is not None:
                            self.target = sense_dep(target)
                        elif target.brty.endswith("A"):
                            self.target = sense_tta(target)
                        elif target.brty.endswith("B"):
                            self.target = sense_ttb(target)
                        elif target.brty.endswith("F"):
                            self.target = sense_ttf(target)
                        else:
                            info = "unknown technology type in %r"
                            raise UnsupportedTargetError(info % target.brty)
                        # Modified code BEGIN
                        if self.target is None:
                            sense_broadcast(target, options.get("broadcast", None))
                        # Modified code END
                    except UnsupportedTargetError as error:
                        if len(targets) == 1:
                            raise error
                        else:
                            log.debug(error)
                    except CommunicationError as error:
                        log.debug(error)
                    else:
                        if self.target is not None:
                            log.debug("found {0}".format(self.target))
                            return self.target
                if len(targets) > 0:
                    self.device.mute()  # deactivate the rf field
                if i < options.get("iterations", 1) - 1:
                    elapsed = time.time() - started
                    time.sleep(max(0, options.get("interval", 0.1) - elapsed))


__all__ = ("BroadcastFrameContactlessFrontend", "RemoteTarget", "ISODEPTag", "activate")
