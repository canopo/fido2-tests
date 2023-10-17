import struct
import time
import sys
import os

import pytest
from fido2.attestation import Attestation
from fido2.client import Fido2Client, _call_polling
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1
from fido2.ctap2 import AttestedCredentialData, PinProtocolV1
from fido2.hid import CtapHidDevice, CTAPHID, TYPE_INIT
from fido2.utils import hmac_sha256, sha256

from tests.utils import *

if "trezor" in sys.argv:
    from .vendor.trezor.udp_backend import force_udp_backend
else:
    from .vendor.solo.udp_backend import force_udp_backend


def pytest_addoption(parser):
    parser.addoption("--sim", action="store_true")
    parser.addoption("--nfc", action="store_true")
    parser.addoption("--experimental", action="store_true")
    parser.addoption("--vendor", default="none")


@pytest.fixture()
def is_simulation(pytestconfig):
    return pytestconfig.getoption("sim")


@pytest.fixture()
def is_nfc(pytestconfig):
    return pytestconfig.getoption("nfc")


@pytest.fixture(scope="module")
def info(device):
    info = device.ctap2.get_info()
    # print("data:", bytes(info))
    # print("decoded:", cbor.decode_from(bytes(info)))
    return info


@pytest.fixture(scope="module")
def MCRes(
    resetDevice,
):
    req = FidoRequest()
    res = resetDevice.sendMC(*req.toMC())
    setattr(res, "request", req)
    return res


@pytest.fixture(scope="class")
def GARes(device, MCRes):
    req = FidoRequest(
        allow_list=[
            {"id": MCRes.auth_data.credential_data.credential_id, "type": "public-key"}
        ]
    )
    res = device.sendGA(*req.toGA())
    setattr(res, "request", req)
    return res


@pytest.fixture(scope="module")
def RegRes(
    resetDevice,
):
    req = FidoRequest()
    res = resetDevice.register(req.challenge, req.appid)
    setattr(res, "request", req)
    return res


@pytest.fixture(scope="class")
def AuthRes(device, RegRes):
    req = FidoRequest()
    res = device.authenticate(req.challenge, req.appid, RegRes.key_handle)
    setattr(res, "request", req)
    return res


@pytest.fixture(scope="module")
def allowListItem(MCRes):
    return


@pytest.fixture(scope="session")
def device(pytestconfig):
    if pytestconfig.getoption("sim"):
        print("FORCE UDP")
        force_udp_backend()

    dev = TestDevice()
    dev.set_sim(pytestconfig.getoption("sim"))

    dev.find_device(pytestconfig.getoption("nfc"))

    return dev


@pytest.fixture(scope="class")
def rebootedDevice(device):
    device.reboot()
    return device


@pytest.fixture(scope="module")
def resetDevice(device):
    device.reset()
    return device


class Packet(object):
    def __init__(self, data):
        self.data = data

    def ToWireFormat(
        self,
    ):
        return self.data

    @staticmethod
    def FromWireFormat(pkt_size, data):
        return Packet(data)

from fido2.pcsc import CtapPcscDevice,_list_readers
from fido2.hid import CAPABILITY, CTAPHID


class MoreRobustPcscDevice(CtapPcscDevice):
    """
    Some small tweaks to prevent failures in NFC when many
    tests are being run on the same connection.
    """
    def __init__(self, connection, name):
        self._capabilities = 0
        self.use_ext_apdu = False
        self._conn = connection
        from smartcard.System import readers
        from smartcard.util import toHexString
        from smartcard.CardConnection import CardConnection
        from smartcard.pcsc.PCSCPart10 import (getFeatureRequest, hasFeature,
            getTlvProperties, FEATURE_CCID_ESC_COMMAND, SCARD_SHARE_DIRECT)
        from smartcard.scard import SCARD_LEAVE_CARD, SCARD_SHARE_EXCLUSIVE, SCARD_CTL_CODE, SCARD_UNPOWER_CARD, SCARD_RESET_CARD

        # res = self._conn.transmit([0xE0,0x00,0x00,0x24,0x02,0x00,0x00],CardConnection.T0_protocol)
        # res = self.control_exchange(SCARD_CTL_CODE(3500), b"\xE0\x00\x00\x24\x00")
        # print('read ctrl res:',res)
        # res = self.control_exchange(SCARD_CTL_CODE(3500), b"\xE0\x00\x00\x24\x02\x00\x00")

        self._conn.connect(
            # CardConnection.T0_protocol,
            # mode=SCARD_SHARE_DIRECT
            # disposition = SCARD_RESET_CARD,
        )

        self._name = name
        self._select()

        # For ACR1252 readers, with drivers installed
        # https://www.acs.com.hk/en/products/342/acr1252u-usb-nfc-reader-iii-nfc-forum-certified-reader
        # disable auto pps, always use 106kbps
        # self.control_exchange(SCARD_CTL_CODE(3500), b"\xE0\x00\x00\x24\x02\x00\x00")
        # or always use 212kps
        # self.control_exchange(SCARD_CTL_CODE(3500), b"\xE0\x00\x00\x24\x02\x01\x01")

        try:  # Probe for CTAP2 by calling GET_INFO
            self.call(CTAPHID.CBOR, b"\x04")
            self._capabilities |= CAPABILITY.CBOR
        except CtapError:
            if self._capabilities == 0:
                raise ValueError("Unsupported device")
    
    def apdu_exchange(self, apdu, protocol = None):
        try:
            return super().apdu_exchange(apdu,protocol)
        except:
            # Try reconnecting..
            self._conn.disconnect()
            self._conn.connect()
            return super().apdu_exchange(apdu,protocol)

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        # Sometimes an NFC reader may suspend the field inbetween tests,
        # Which would require the app to be selected again.
        self._select()
        return super().call(cmd, data, event, on_keepalive)

    def _call_cbor(self, data=b"", event=None, on_keepalive=None):
        # Sometimes an NFC reader may suspend the field inbetween tests,
        # Which would require the app to be selected again.
        self._select()
        return super()._call_cbor(data, event, on_keepalive)

    @classmethod
    def list_devices(cls, name=""):
        for reader in _list_readers():
            if name in reader.name:
                try:
                    yield cls(reader.createConnection(), reader.name)
                except Exception as e:
                    print(e)

class TestDevice:
    def __init__(self, tester=None):
        self.origin = "https://examplo.org"
        self.host = "examplo.org"
        self.user_count = 10
        self.is_sim = False
        self.is_nfc = False
        self.nfc_interface_only = False
        if tester:
            self.initFrom(tester)

    def initFrom(self, tester):
        self.user_count = tester.user_count
        self.is_sim = tester.is_sim
        self.is_nfc = tester.is_nfc
        self.dev = tester.dev
        self.ctap2 = tester.ctap2
        self.ctap1 = tester.ctap1
        self.client = tester.client
        self.nfc_interface_only = tester.nfc_interface_only

    def find_device(self, nfcInterfaceOnly=False):
        dev = None
        self.nfc_interface_only = nfcInterfaceOnly
        if not nfcInterfaceOnly:
            print("--- HID ---")
            print(list(CtapHidDevice.list_devices()))
            dev = next(CtapHidDevice.list_devices(), None)

        else:
            from fido2.pcsc import CtapPcscDevice

            print("--- NFC ---")
            dev = next(MoreRobustPcscDevice.list_devices(), None)

            if dev:
                self.is_nfc = True
                # For ACR1252 readers, with drivers installed
                # https://www.acs.com.hk/en/products/342/acr1252u-usb-nfc-reader-iii-nfc-forum-certified-reader
                # disable auto pps, always use 106kbps
                # dev.control_exchange(SCARD_CTL_CODE(0x3500), b"\xE0\x00\x00\x24\x02\x00\x00")

        if not dev:
            raise RuntimeError("No FIDO device found")
        self.dev = dev
        self.client = Fido2Client(dev, self.origin)
        self.ctap2 = self.client.ctap2
        self.ctap1 = CTAP1(dev)

    def set_user_count(self, count):
        self.user_count = count

    def set_sim(self, b):
        self.is_sim = b

    def reboot(
        self,
    ):
        if self.is_sim:
            print("Sending restart command...")
            self.send_magic_reboot()
            TestDevice.delay(0.25)
            return

        if "canokeys" in sys.argv:
            if self.is_nfc:
                if self.send_nfc_reboot():
                    TestDevice.delay(1)
                    self.find_device(self.nfc_interface_only)
                    return
            try:
                os.system("STM32_Programmer_CLI -c port=SWD  -rst")
                TestDevice.delay(2)
                self.find_device(self.nfc_interface_only)
            except OSError:
                pass
        elif "solokeys" in sys.argv or "solobee" in sys.argv:
            if self.is_nfc:
                if self.send_nfc_reboot():
                    TestDevice.delay(1)
                    self.find_device(self.nfc_interface_only)
                    return
            try:
                self.dev.call(0x53 ^ 0x80, b"")
            except OSError:
                pass

            print("Rebooting..")
            for i in range(0, 10):
                time.sleep(0.1 * i)
                try:
                    self.find_device(self.nfc_interface_only)
                    return
                except (RuntimeError, FileNotFoundError):
                    pass
        else:
            print("Please reboot authenticator and hit enter")
            input()
            self.find_device(self.nfc_interface_only)

    def send_data(self, cmd, data, timeout = 1.0, on_keepalive = None):
        if not isinstance(data, bytes):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        with Timeout(timeout) as event:
            event.is_set()
            return self.dev.call(cmd, data, event, on_keepalive = on_keepalive)

    def send_raw(self, data, cid=None):
        if cid is None:
            cid = struct.pack(">I", self.dev._channel_id)
        elif not isinstance(cid, bytes):
            cid = struct.pack("%dB" % len(cid), *[ord(x) for x in cid])
        if not isinstance(data, bytes):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        data = cid + data
        l = len(data)
        if l != 64:
            pad = "\x00" * (64 - l)
            pad = struct.pack("%dB" % len(pad), *[ord(x) for x in pad])
            data = data + pad
        assert len(data) == 64
        self.dev._connection.write_packet(data)

    def send_magic_reboot(
        self,
    ):
        """
        For use in simulation and testing.  Random bytes that authenticator should detect
        and then restart itself.
        """
        magic_cmd = (
            b"\xac\x10\x52\xca\x95\xe5\x69\xde\x69\xe0\x2e\xbf"
            + b"\xf3\x33\x48\x5f\x13\xf9\xb2\xda\x34\xc5\xa8\xa3"
            + b"\x40\x52\x66\x97\xa9\xab\x2e\x0b\x39\x4d\x8d\x04"
            + b"\x97\x3c\x13\x40\x05\xbe\x1a\x01\x40\xbf\xf6\x04"
            + b"\x5b\xb2\x6e\xb7\x7a\x73\xea\xa4\x78\x13\xf6\xb4"
            + b"\x9a\x72\x50\xdc"
        )
        self.dev._connection.write_packet(magic_cmd)

    def send_err_injection(self, data, p1=0, p2=0):
        if self.is_sim:
            cmd = b"\x99\x10\x52\xca\x95\xe5\x69\xde\x69\xe0\x2e\xbf"
            cmd += struct.pack("2B", p1, p2)
            cmd += data
            self.dev._connection.write_packet(cmd)
        elif self.is_nfc:
            header = b"\x00\xef" + struct.pack("3B", p1, p2, len(data))
            resp, sw1, sw2 = self.dev.apdu_exchange(header + data)
            return sw1 == 0x90 and sw2 == 0x00
        else:
            pass #TODO: HID

    def send_nfc_reboot(
        self,
    ):
        """
        Send magic nfc reboot sequence for solokey, or reboot command for solov2.
        """

        from smartcard.Exceptions import NoCardException, CardConnectionException

        if "solokeys" in sys.argv or "canokeys" in sys.argv:
            header = b"\x00\xee\x00\x00\x04"
            data = b"\x12\x56\xab\xf0"
            resp, sw1, sw2 = self.dev.apdu_exchange(header + data)
            return sw1 == 0x90 and sw2 == 0x00
        else:
            # Select root app
            apdu = b"\x00\xA4\x04\x00\x09\xA0\x00\x00\x08\x47\x00\x00\x00\x01"
            resp, sw1, sw2 = self.dev._conn.transmit(list(apdu))
            did_select = (sw1 == 0x90 and sw2 == 0x00)
            if not did_select:
                return False

            # Send reboot command
            apdu = b"\x00\x53\x00\x00"
            try:
                resp, sw1, sw2 = self.dev._conn.transmit(list(apdu))
                return sw1 == 0x90 and sw2 == 0x00
            except (NoCardException, CardConnectionException):
                return True

    def cid(
        self,
    ):
        return struct.pack(">I", self.dev._channel_id)

    def set_cid(self, cid):
        if isinstance(cid, str):
            cid = bytes(cid, encoding="raw_unicode_escape")
        self.dev._channel_id = struct.unpack_from(">I", cid)[0]

# recv_raw from:
#   https://github.com/Yubico/python-fido2/blob/5cd89c999aa556770b0c3a83f6ac238dca4e8df5/fido2/hid/__init__.py#L154
# Copyright (c) 2020 Yubico AB
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

    def recv_raw(
        self,
    ):
        with Timeout(1.0):
            seq = 0
            response = None
            while True:

                recv = self.dev._connection.read_packet()
                r_channel = struct.unpack_from(">I", recv)[0]
                recv = recv[4:]
                if r_channel != self.dev._channel_id:
                    continue

                if response is None:  # Initialization packet
                    r_cmd, r_len = struct.unpack_from(">BH", recv)
                    recv = recv[3:]
                    if (r_cmd & TYPE_INIT) != 0:
                        cmd = r_cmd
                        response = b""
                    else:
                        raise CtapError(CtapError.ERR.INVALID_COMMAND)
                else:  # Continuation packet
                    r_seq = struct.unpack_from(">B", recv)[0]
                    recv = recv[1:]
                    if r_seq != seq:
                        raise Exception("Wrong sequence number")
                    seq += 1

                response += recv
                if len(response) >= r_len:
                    break

            return cmd, response[:r_len]

    def check_error(data, err=None):
        assert len(data) == 1
        if err is None:
            if data[0] != 0:
                raise CtapError(data[0])
        elif data[0] != err:
            raise ValueError("Unexpected error: %02x" % data[0])

    def register(self, chal, appid, on_keepalive=DeviceSelectCredential(1)):
        reg_data = _call_polling(
            0.25, None, on_keepalive, self.ctap1.register, chal, appid
        )
        return reg_data

    def authenticate(
        self,
        chal,
        appid,
        key_handle,
        check_only=False,
        on_keepalive=DeviceSelectCredential(1),
    ):
        auth_data = _call_polling(
            0.25,
            None,
            on_keepalive,
            self.ctap1.authenticate,
            chal,
            appid,
            key_handle,
            check_only=check_only,
        )
        return auth_data

    def reset(
        self,
    ):
        print("Resetting Authenticator...")
        try:
            self.ctap2.reset(on_keepalive=DeviceSelectCredential(1))
        except CtapError:
            # Some authenticators need a power cycle
            print("Need to power cycle authentictor to reset..")
            self.reboot()
            self.ctap2.reset(on_keepalive=DeviceSelectCredential(1))

    def sendMC(self, *args, **kwargs):

        if len(args) > 11:
            # Add additional arg to calculate pin auth on demand
            pin = args[-1]
            args = list(args[:-1])
            if args[7] == None and args[8] == None:
                pin_token = self.client.client_pin.get_pin_token(pin)
                pin_auth = hmac_sha256(pin_token, args[0])[:16]
                args[7] = pin_auth
                args[8] = 1

        attestation_object = self.ctap2.make_credential(*args, **kwargs)
        if attestation_object:
            verifier = Attestation.for_type(attestation_object.fmt)
            client_data = args[0]
            verifier().verify(
                attestation_object.att_statement,
                attestation_object.auth_data,
                client_data,
            )
        return attestation_object

    def sendGA(self, *args, **kwargs):
        if len(args) > 9:
            # Add additional arg to calculate pin auth on demand
            pin = args[-1]
            args = list(args[:-1])
            if args[5] == None and args[6] == None:
                pin_token = self.client.client_pin.get_pin_token(pin)
                pin_auth = hmac_sha256(pin_token, args[1])[:16]
                args[5] = pin_auth
                args[6] = 1

        return self.ctap2.get_assertion(*args, **kwargs)

    def sendCP(self, *args, **kwargs):
        return self.ctap2.client_pin(*args, **kwargs)

    def sendPP(self, *args, **kwargs):
        return self.client.client_pin.get_pin_token(*args, **kwargs)

    def delay(secs):
        time.sleep(secs)
