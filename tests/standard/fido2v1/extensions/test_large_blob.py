import pytest
import struct
from binascii import unhexlify, hexlify

from fido2.ctap import CtapError
from fido2.ctap2 import LargeBlobs
from fido2.ctap2.pin import ClientPin, PinProtocolV1
from fido2.utils import hmac_sha256, sha256
from tests.utils import *

PIN = "654321"

@pytest.fixture(scope="class")
def MC_LB_Res(
    resetDevice,
):
    resetDevice.client.client_pin.set_pin(PIN)

    rp = {"id": "ID:ReqDCWithLargeBlob", "name": "ReqDCWithLargeBlob"}
    req = FidoRequest(options={'rk': True}, rp=rp, extensions={"largeBlobKey": True}, pin=PIN)
    res = resetDevice.sendMC(*req.toMC())
    setattr(res, "request", req)
    return res

@pytest.fixture(scope = 'function')
def LB_OP(device):
    pin_protocol = PinProtocolV1()
    return LargeBlobs(device.ctap2, pin_protocol, device.sendPP(PIN, ClientPin.PERMISSION.LARGE_BLOB_WRITE))

@pytest.fixture(scope = 'class')
def RAW_CMD(device):
    return device.ctap2.large_blobs

class TestLargeBlob(object):
    def test_get_info(self, info):
        print(info)
        assert "FIDO_2_1" in info.versions
        assert "largeBlobKey" in info.extensions
        assert "largeBlobs" in info.options and info.options['largeBlobs']

    def test_simple_write(self, resetDevice, info, RAW_CMD):
        data = unhexlify('8076be8b528d0075f7aae98d6fa57a6d3c')
        RAW_CMD(offset = 0, set = data, length = 17)
        ret = RAW_CMD(offset = 0, get = 17)
        assert ret[1] == data

        data = b'\x00' + data[1:]
        with pytest.raises(CtapError) as e:
            RAW_CMD(offset = 0, set = data, length = 17)
        assert e.value.code == CtapError.ERR.INTEGRITY_FAILURE

    def test_make_credential_with_lb(self, device, MC_LB_Res):
        LBKey = MC_LB_Res.large_blob_key
        assert len(LBKey) == 32

        req = FidoRequest(MC_LB_Res.request, options=None)
        ga = device.sendGA(*req.toGA())
        LBKey2 = ga.large_blob_key
        assert LBKey2 == LBKey

        req = FidoRequest(options={'rk': False}, extensions={"largeBlobKey": True}, pin=PIN)
        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())
        assert e.value.code == CtapError.ERR.INVALID_OPTION

    def test_blob_array_rw(self, device, info, LB_OP):
        max_large_blob = info.max_large_blob
        byte_len = max_large_blob - 30
        test_data = [byte_len*'s']
        LB_OP.write_blob_array(test_data)

        read_back = LB_OP.read_blob_array()
        assert read_back == test_data

    def test_invalid_parameters(self, device, info, RAW_CMD):
        max_large_blob = info.max_large_blob
        max_frag_size = info.max_msg_size - 64
        kwargs_list = [
            {"offset": None, "get": 100},
            {"offset": 0},
            {"offset": 0, "get": 100, "set": b"x"*20},
            {"offset": 0, "get": 100, "length": 1},
            {"offset": 0, "get": 100, "pin_uv_protocol": 1},
            {"offset": 0, "get": 100, "pin_uv_param": b'xxxxxxxx'},
            {"offset": 0, "get": 2**30},
            {"offset": 2**30, "get": 20},
            {"offset": 0, "set": b'x'*(max_frag_size+1), "length": max_large_blob},
            {"offset": 0, "set": b'x', "length": 2**30},
            {"offset": 0, "set": b'x', "length": 16},
            {"offset": 0, "set": b'x', "length": 0},
            {"offset": 10, "set": b'x', "length": 1000},
        ]
        for kwargs in kwargs_list:
            with pytest.raises(CtapError) as e:
                RAW_CMD(**kwargs)
            if ("get" in kwargs and kwargs["get"] > max_frag_size) or \
                ("set" in kwargs and len(kwargs["set"]) > max_frag_size):
                assert e.value.code == CtapError.ERR.INVALID_LENGTH
            elif ("length" in kwargs and kwargs["length"] > max_large_blob):
                assert e.value.code == CtapError.ERR.LARGE_BLOB_STORAGE_FULL
            else:
                assert e.value.code == CtapError.ERR.INVALID_PARAMETER

    def _calc_pin_auth(self, token, offset, data):
        msg = b"\xff" * 32 + b"\x0c\x00" \
            + struct.pack("<I", offset)  \
            + sha256(data)
        return PinProtocolV1().authenticate(token, msg)

    def test_wrong_offset_during_write(self, device, MC_LB_Res, RAW_CMD):
        token = device.sendPP(PIN, ClientPin.PERMISSION.LARGE_BLOB_WRITE)

        RAW_CMD(offset=0, set=b'xxx', length=17, 
            pin_uv_protocol=1, pin_uv_param=self._calc_pin_auth(token, 0, b'xxx'))
        with pytest.raises(CtapError) as e:
            RAW_CMD(offset=4, set=b'xxx')
        assert e.value.code == CtapError.ERR.INVALID_SEQ
        data = b'x'*17
        with pytest.raises(CtapError) as e:
            RAW_CMD(offset=3, set=data, 
                pin_uv_protocol=1, pin_uv_param=self._calc_pin_auth(token, 3, data))
        assert e.value.code == CtapError.ERR.INVALID_PARAMETER

    def test_auth(self, device, MC_LB_Res, RAW_CMD):
        with pytest.raises(CtapError) as e:
            RAW_CMD(offset=0, set=b'xxx', length=17)
        assert e.value.code == CtapError.ERR.PUAT_REQUIRED
        with pytest.raises(CtapError) as e:
            RAW_CMD(offset=0, set=b'xxx', length=17, pin_uv_param=16*b'U')
        assert e.value.code == CtapError.ERR.MISSING_PARAMETER
        with pytest.raises(CtapError) as e:
            RAW_CMD(offset=0, set=b'xxx', length=17, pin_uv_protocol=99, pin_uv_param=16*b'U')
        assert e.value.code == CtapError.ERR.INVALID_PARAMETER

        token = device.sendPP(PIN, ClientPin.PERMISSION.LARGE_BLOB_WRITE)
        data = b'x'*17
        with pytest.raises(CtapError) as e:
            RAW_CMD(offset=0, set=data, length=17,
                pin_uv_protocol=1, pin_uv_param=self._calc_pin_auth(token, 8, data))
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID # wrong auth data

        token = device.sendPP(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
        data = b'x'*17
        with pytest.raises(CtapError) as e:
            RAW_CMD(offset=0, set=data, length=17,
                pin_uv_protocol=1, pin_uv_param=self._calc_pin_auth(token, 0, data))
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID # wrong permission

