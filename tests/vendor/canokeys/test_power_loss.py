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

class TestPowerLoss(object):

    def test_make_cred(self, device, PinToken, CredMgmt):
        mc_req = FidoRequest(
            pin=PIN,
            rp={'id': 'power-loss.test'},
            options={"rk": True},
        )
        device.send_err_injection(b"ctap_dm")
        with pytest.raises(CtapError) as e:
            mc_res = device.sendMC(*mc_req.toMC())
        assert e.value.code == 0xF1
        device.reboot()

        nr_dc = 0
        try:
            ga_req = FidoRequest(mc_req, options=None)
            device.sendGA(*ga_req.toGA())
            nr_dc = 1
        except CtapError as e:
            assert e.code == CtapError.ERR.NO_CREDENTIALS

        CredMgmt.pin_uv_token = device.sendPP(PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        assert nr_dc == CredMgmt.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT]

        res = CredMgmt.enumerate_rps()
        cnt = 0
        for d in res:
            rpid = d[CredentialManagement.RESULT.RP]["id"]
            if rpid == mc_req.rp['id']:
                print("Match RpID:", rpid)
                cnt += 1
        assert cnt == nr_dc
            
        mc_req = FidoRequest(
            pin=PIN,
            rp={'id': 'power-loss2.test'},
            options={"rk": True},
        )
        device.send_err_injection(b"ctap_dc")
        with pytest.raises(CtapError) as e:
            mc_res = device.sendMC(*mc_req.toMC())
        assert e.value.code == 0xF1
        device.reboot()

        with pytest.raises(CtapError) as e:
            ga_req = FidoRequest(mc_req, options=None)
            device.sendGA(*ga_req.toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

        CredMgmt.pin_uv_token = device.sendPP(PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        assert nr_dc == CredMgmt.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT]

    def test_del_cred(self, device, PinToken, CredMgmt):
        mc_req = FidoRequest(
            pin=PIN,
            rp={'id': 'power-loss.test'},
            options={"rk": True},
        )
        mc_res1 = device.sendMC(*mc_req.toMC())
        mc_req.user = generate_user()
        mc_res2 = device.sendMC(*mc_req.toMC())
        nr_dc = 2

        CredMgmt.pin_uv_token = device.sendPP(PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        assert nr_dc == CredMgmt.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
        assert 1 == len(CredMgmt.enumerate_rps())
        creds = CredMgmt.enumerate_creds(sha256(mc_req.rp['id'].encode("utf8")))
        assert len(creds) == nr_dc

        device.send_err_injection(b"ctap_dm")
        with pytest.raises(CtapError) as e:
            CredMgmt.delete_cred({
                "id": mc_res1.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            })
        assert e.value.code == 0xF1
        device.reboot()
        nr_dc -= 1

        CredMgmt.pin_uv_token = device.sendPP(PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        assert nr_dc == CredMgmt.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
        assert 1 == len(CredMgmt.enumerate_rps())
        creds = CredMgmt.enumerate_creds(sha256(mc_req.rp['id'].encode("utf8")))
        assert len(creds) == nr_dc

        device.send_err_injection(b"ctap_dc")
        with pytest.raises(CtapError) as e:
            CredMgmt.delete_cred({
                "id": mc_res2.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            })
        assert e.value.code == 0xF1
        device.reboot()
        nr_dc -= 1
        
        CredMgmt.pin_uv_token = device.sendPP(PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        assert nr_dc == CredMgmt.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
        assert 0 == len(CredMgmt.enumerate_rps())
