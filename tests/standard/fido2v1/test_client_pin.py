
import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import AttestedCredentialData, ClientPin

from tests.utils import *

@pytest.fixture(scope = 'module')
def rebootDevice(request, device):
    device.reboot()
    return device

@pytest.mark.skipif(
    "trezor" in sys.argv, reason="ClientPin is not supported on Trezor."
)
class TestClientPin(object):
    @pytest.mark.parametrize(
        "protocolVer", [1, 2]
    )
    def test_set_pin_with_illegal_args(self, protocolVer, rebootDevice, info):
        if protocolVer not in info.pin_uv_protocols:
            return
        rebootDevice.reset()
        client_pin = self._get_client_pin(rebootDevice, protocolVer)
        with pytest.raises(CtapError) as e:
            client_pin.set_pin(64*'X')
        assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION
        with pytest.raises(CtapError) as e:
            client_pin.set_pin('XXX\x00')
        assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION

        key_agreement, shared_secret = client_pin._get_shared_secret()
        pin_enc = client_pin.protocol.encrypt(shared_secret, 64*b'X')
        pin_uv_param = client_pin.protocol.authenticate(shared_secret, pin_enc)

        bad_pin_uv_param = pin_uv_param[:-8] + 8*b'U'
        with pytest.raises(CtapError) as e:
            client_pin.ctap.client_pin(
                client_pin.protocol.VERSION,
                ClientPin.CMD.SET_PIN,
                key_agreement=key_agreement,
                new_pin_enc=pin_enc,
                pin_uv_param=bad_pin_uv_param,
            )
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        bad_pin_enc = 8*b'2' + pin_enc[8:]
        with pytest.raises(CtapError) as e:
            client_pin.ctap.client_pin(
                client_pin.protocol.VERSION,
                ClientPin.CMD.SET_PIN,
                key_agreement=key_agreement,
                new_pin_enc=bad_pin_enc,
                pin_uv_param=pin_uv_param,
            )
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    @pytest.mark.parametrize(
        "protocolVer", [1, 2]
    )
    def test_change_pin_with_illegal_args(self, protocolVer, rebootDevice, info):
        PIN = '1234'
        if protocolVer not in info.pin_uv_protocols:
            return
        rebootDevice.reset()
        client_pin = self._get_client_pin(rebootDevice, protocolVer)
        client_pin.set_pin(PIN)

        with pytest.raises(CtapError) as e:
            client_pin.change_pin(PIN, 64*'X')
        assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION
        with pytest.raises(CtapError) as e:
            client_pin.change_pin(PIN, 'XXX\x00')
        assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION

        key_agreement, shared_secret = client_pin._get_shared_secret()
        pin_hash = sha256(PIN.encode())[:16]
        pin_hash_enc = client_pin.protocol.encrypt(shared_secret, pin_hash)
        new_pin_enc = client_pin.protocol.encrypt(shared_secret, 64*b'X')
        pin_uv_param = client_pin.protocol.authenticate(
            shared_secret, new_pin_enc + pin_hash_enc
        )
        bad_pin_uv_param = pin_uv_param[:-8] + 8*b'U'
        with pytest.raises(CtapError) as e:
            client_pin.ctap.client_pin(
                client_pin.protocol.VERSION,
                ClientPin.CMD.CHANGE_PIN,
                key_agreement=key_agreement,
                pin_hash_enc=pin_hash_enc,
                new_pin_enc=new_pin_enc,
                pin_uv_param=bad_pin_uv_param,
            )
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    def test_change_pin_with_wrong_pin(self, device, info):
        correct_pin = 63*'T'
        device.reset()
        protocolVer = info.pin_uv_protocols[0]
        client_pin = self._get_client_pin(device, protocolVer)
        client_pin.set_pin(correct_pin)

        for i in range(1,10):
            if i <= 2:
                with pytest.raises(CtapError) as e:
                    client_pin.change_pin('eeeee', 'NNNNN')
                assert e.value.code == CtapError.ERR.PIN_INVALID
            elif i == 3:
                new_pin = 4*'0'
                try_pin = correct_pin
                client_pin.change_pin(correct_pin, new_pin)
                correct_pin = new_pin
            elif i <= 7:
                if i == 7:
                    try_pin = correct_pin
                with pytest.raises(CtapError) as e:
                    client_pin.change_pin(try_pin, 'NNNNN')
                if i == 6 or i == 7:
                    # After pinAuth is blocked, even correct PIN doesn't work
                    assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED
                else:
                    assert e.value.code == CtapError.ERR.PIN_INVALID
            elif i == 8:
                device.reboot()
                client_pin = self._get_client_pin(device, protocolVer)
                with pytest.raises(CtapError) as e:
                    client_pin.change_pin('wrong', 'NNNNN')
                assert e.value.code == CtapError.ERR.PIN_INVALID

                client_pin.change_pin(correct_pin, 'NNNNN')

    def _get_client_pin(self, device, protocolVer):
        for proto in ClientPin.PROTOCOLS:
            if proto.VERSION == protocolVer:
                break
        client_pin = ClientPin(device.ctap2, proto())
        return client_pin
