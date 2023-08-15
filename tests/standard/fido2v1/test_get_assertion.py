import pytest
from cryptography.exceptions import InvalidSignature
from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin
from fido2.utils import hmac_sha256, sha256

from tests.utils import *

PIN = "123456"

@pytest.fixture(params=[PIN], scope = 'module')
def SetPin(request, device):
    device.reboot()
    device.reset()
    pin = request.param
    device.client.client_pin.set_pin(pin)

class TestGetAssertion(object):

    def test_get_assertion_uv_true(self, resetDevice):
        req = FidoRequest(options={"uv": True})
        with pytest.raises(CtapError) as e:
            resetDevice.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.INVALID_OPTION

    def test_get_assertion_rk_true(self, resetDevice):
        req = FidoRequest(options={"rk": True})
        with pytest.raises(CtapError) as e:
            resetDevice.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.UNSUPPORTED_OPTION

        req = FidoRequest(options={"rk": False})
        with pytest.raises(CtapError) as e:
            resetDevice.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.UNSUPPORTED_OPTION

    def test_get_assertion_zero_len_auth(self, resetDevice):
        req = FidoRequest(pin_protocol=1, pin_auth=b'')
        with pytest.raises(CtapError) as e:
            resetDevice.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.PIN_NOT_SET

    def test_get_assertion_zero_len_auth_when_pin_set(self, device, SetPin):
        req = FidoRequest(pin_protocol=1, pin_auth=b'')
        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.PIN_INVALID

    def test_get_assertion_missing_protocol(self, device):
        req = FidoRequest(pin_protocol=None, pin_auth=b'x')
        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    def test_get_assertion_invalid_auth(self, device, info, SetPin):
        for protocol in [1, 2]:
            req = FidoRequest(pin_protocol=protocol, pin_auth=16*b'\x55')
            with pytest.raises(CtapError) as e:
                device.sendGA(*req.toGA())
            assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        rp = {"id": "example_3.com", "name": "John Doe 2"}
        req = FidoRequest(
            pin=PIN,
            options={"rk": True},
            rp=rp,
        )
        res = device.sendMC(*req.toMC())
        assert (res.auth_data.flags & 5) == 5

        allow_list = [{
            "id": res.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }]

        # incorrect permission
        pin_token = device.client.client_pin.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
        req = FidoRequest(req, options=None, pin=None, pin_protocol=1, pin_auth=hmac_sha256(pin_token, req.cdh)[:16])
        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # correct permission and rpId
        pin_token = device.client.client_pin.get_pin_token(PIN, ClientPin.PERMISSION.GET_ASSERTION, rp['id'])
        req = FidoRequest(req, options={"up": False}, pin_protocol=1, pin_auth=hmac_sha256(pin_token, req.cdh)[:16])
        res = device.sendGA(*req.toGA())
        assert (res.auth_data.flags & 5) == 4

        # incorrect rpId (token was associated with "example_3.com")
        req = FidoRequest(req, rp = {"id": "n.com", "name": "Lee"})
        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # consumes userVerifiedFlag
        req = FidoRequest(req, rp = rp, options=None)
        device.sendGA(*req.toGA())

        # userVerifiedFlagValue is false
        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # incorrect rpId
        pin_token = device.client.client_pin.get_pin_token(PIN, ClientPin.PERMISSION.GET_ASSERTION, rp['id'])
        req = FidoRequest(req, rp = {"id": "n.com", "name": "Lee"}, pin_auth=hmac_sha256(pin_token, req.cdh)[:16])
        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # incorrect rpId
        pin_token = device.client.client_pin.get_pin_token(PIN, ClientPin.PERMISSION.GET_ASSERTION, "others.com")
        req = FidoRequest(req, rp = rp, pin_auth=hmac_sha256(pin_token, req.cdh)[:16])
        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID





