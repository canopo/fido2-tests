import pytest
import time
import random
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1
from fido2.utils import hmac_sha256, sha256
from tests.utils import *
from binascii import hexlify

class TestUnsupported(object):
    def test_unsupported_cmds(self, info, device):
        assert "authnrCfg" not in info.options
        with pytest.raises(CtapError) as e:
            device.ctap2.send_cbor(Ctap2.CMD.CONFIG)
        assert e.value.code == CtapError.ERR.VENDOR_FIRST+1

        with pytest.raises(CtapError) as e:
            device.ctap2.send_cbor(Ctap2.CMD.BIO_ENROLLMENT)
        assert e.value.code == CtapError.ERR.VENDOR_FIRST+1

    def test_back_compatible_cmds(self, info, device):
        with pytest.raises(CtapError) as e:
            device.ctap2.send_cbor(Ctap2.CMD.CREDENTIAL_MGMT_PRE)
        assert e.value.code == CtapError.ERR.INVALID_CBOR
