import pytest
import time
import random
from fido2.cose import EdDSA, ES256
from fido2.ctap import CtapError
from fido2.ctap2 import CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV1
from fido2.utils import hmac_sha256, sha256
from tests.utils import *
from binascii import hexlify

PIN = "123456"

@pytest.fixture(params=[PIN], scope = 'function')
def PinToken(request, device):
    device.reboot()
    device.reset()
    pin = request.param
    device.client.client_pin.set_pin(pin)
    return device.client.client_pin.get_pin_token(pin)

def _get_pin_token_with_CM_permission(device):
    return device.sendPP(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)

@pytest.fixture(scope = 'function')
def CredMgmt(device, PinToken):
    pin_protocol = PinProtocolV1()
    return CredentialManagement(device.ctap2, pin_protocol, _get_pin_token_with_CM_permission(device))

class TestVendorSpecificCredentialManagement(object):

    def test_truncated_rpid(self, device, PinToken, CredMgmt):
        cases = [
            ("example.com", "example.com"),
            ("myfidousingwebsite.hostingprovider.net", "…ngwebsite.hostingprovider.net"),
            ("mygreatsite.hostingprovider.info", "mygreatsite.hostingprovider.info"),
            ("otherprotocol://myfidousingwebsite.hostingprovider.net", "otherprotocol:…ingprovider.net"),
            ("veryexcessivelylargeprotocolname://example.com", "veryexcessivelylargeprotocolname"),
        ]
        for o in cases:
            mc_req = FidoRequest(
                pin=PIN,
                options={"rk": True},
                rp={"id": o[0]},
                key_params=[{"type": "public-key", "alg": EdDSA.ALGORITHM}]
            )
            mc_res = device.sendMC(*mc_req.toMC())

        CredMgmt.pin_uv_token = device.sendPP(PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        res = CredMgmt.enumerate_rps()
        cnt = 0
        for d in res:
            rpid = d[CredentialManagement.RESULT.RP]["id"]
            for o in cases:
                if rpid == o[0] or rpid == o[1]:
                    print("Match RpID:", rpid)
                    assert d[CredentialManagement.RESULT.RP_ID_HASH] == sha256(o[0].encode('ascii'))
                    cnt += 1
                    break
            else:
                print("Extra RpID:", rpid)
        assert cnt == len(cases)
        