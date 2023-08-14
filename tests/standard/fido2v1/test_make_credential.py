import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import AttestedCredentialData, PinProtocolV1
from fido2.ctap2.pin import ClientPin
from fido2.cose import EdDSA, ES256
from fido2.utils import hmac_sha256, sha256

from tests.utils import FidoRequest, verify

PIN = "123456"

@pytest.fixture(params=[PIN], scope = 'module')
def SetPin(request, device):
    device.reboot()
    device.reset()
    pin = request.param
    device.client.client_pin.set_pin(pin)

class TestMakeCredentialV2_1(object):
    def test_make_credential_uv_true(self, device):
        req = FidoRequest(options={"uv": True})
        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())
        assert e.value.code == CtapError.ERR.INVALID_OPTION

    def test_make_credential_up_false(self, device):
        req = FidoRequest(options={"up": False})
        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())
        assert e.value.code == CtapError.ERR.INVALID_OPTION

    def test_make_credential_zero_len_auth(self, resetDevice):
        req = FidoRequest(pin_protocol=1, pin_auth=b'')
        with pytest.raises(CtapError) as e:
            resetDevice.sendMC(*req.toMC())
        assert e.value.code == CtapError.ERR.PIN_NOT_SET

    def test_make_credential_zero_len_auth_when_pin_set(self, device, SetPin):
        req = FidoRequest(pin_protocol=1, pin_auth=b'')
        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())
        assert e.value.code == CtapError.ERR.PIN_INVALID

    def test_make_credential_without_pin(self, device, info, SetPin):
        
        if 'alwaysUv' in info.options and info.options['alwaysUv']:
            # skip this test
            return
        req = FidoRequest(rp={"id": "test.org", "name": "n"})

        if 'makeCredUvNotRqd' in info.options and info.options['makeCredUvNotRqd']:
            # Works without pin verification
            res = device.sendMC(*req.toMC())
            assert (res.auth_data.flags & 5) == 1 # UV is 0

            req = FidoRequest(req, options={"rk": True})
            with pytest.raises(CtapError) as e:
                device.sendMC(*req.toMC())
            if 'noMcGaPermissionsWithClientPin' not in info.options or not info.options['noMcGaPermissionsWithClientPin']:
                assert e.value.code == CtapError.ERR.PUAT_REQUIRED
            else:
                assert e.value.code == CtapError.ERR.OPERATION_DENIED
        else:
            with pytest.raises(CtapError) as e:
                device.sendMC(*req.toMC())
            if 'noMcGaPermissionsWithClientPin' not in info.options or not info.options['noMcGaPermissionsWithClientPin']:
                assert e.value.code == CtapError.ERR.PUAT_REQUIRED
            else:
                assert e.value.code == CtapError.ERR.OPERATION_DENIED

    def test_make_credential_invalid_auth(self, device, info, SetPin):
        for protocol in [1, 2]:
            req = FidoRequest(pin_protocol=protocol, pin_auth=16*b'\x55')
            with pytest.raises(CtapError) as e:
                device.sendMC(*req.toMC())
            assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        rp = {"id": "example_3.com", "name": "John Doe 2"}
        req = FidoRequest(
            pin=PIN,
            options={"rk": True},
            rp=rp,
        )
        res = device.sendMC(*req.toMC())
        assert (res.auth_data.flags & 5) == 5

        # incorrect permission
        pin_token = device.client.client_pin.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
        req = FidoRequest(req, pin=None, pin_protocol=1, pin_auth=hmac_sha256(pin_token, req.cdh)[:16])
        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # correct permission and rpId
        pin_token = device.client.client_pin.get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, "example_3.com")
        req = FidoRequest(req, pin_auth=hmac_sha256(pin_token, req.cdh)[:16])
        res = device.sendMC(*req.toMC())
        assert (res.auth_data.flags & 5) == 5

        # userVerifiedFlagValue is false
        req = FidoRequest(req, rp = {"id": "example_3.com", "name": "Lee"})
        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # incorrect rpId
        req = FidoRequest(req, rp = {"id": "n.com", "name": "Lee"})
        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        # incorrect rpId
        pin_token = device.client.client_pin.get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, "others.com")
        req = FidoRequest(req, rp = {"id": "example_3.com", "name": "Alice"}, pin_auth=hmac_sha256(pin_token, req.cdh)[:16])
        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID



