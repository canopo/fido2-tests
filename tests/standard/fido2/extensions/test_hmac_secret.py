import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fido2.ctap import CtapError
from fido2.utils import hmac_sha256, sha256

from tests.utils import FidoRequest, shannon_entropy, verify, generate_user

class HmacSecretCipher(Cipher):
    def __init__(self, shared_secret, ver_pin_proto):
        self.ver_pin_proto = ver_pin_proto
        self.enc_iv = bytes(range(16)) if self.ver_pin_proto == 2 else b"\x00" * 16

        if ver_pin_proto == 2:
            # The second key should be used in Pin Protocol V2
            shared_secret = shared_secret[32:]
        Cipher.__init__(
            self, algorithms.AES(shared_secret), modes.CBC(self.enc_iv), default_backend()
        )
        
    def get_iv(self):
        return self.mode.initialization_vector if self.ver_pin_proto == 2 else b''
    
    def hs_decrypt(self, data):
        iv = data[:16] if self.ver_pin_proto == 2 else b"\x00" * 16
        self.mode = modes.CBC(iv)
        if self.ver_pin_proto == 2:
            data = data[16:]

        dec = self.decryptor()
        result = dec.update(data) + dec.finalize()
        return result

    def encryptor(self):
        self.mode = modes.CBC(self.enc_iv)
        return Cipher.encryptor(self)

def get_salt_params(cipher, shared_secret, salts):
    enc = cipher.encryptor()
    salt_enc = cipher.get_iv()
    for salt in salts:
        salt_enc += enc.update(salt)
    salt_enc += enc.finalize()

    if len(shared_secret) == 64:
        # The first key (hmac key) should be used in Pin Protocol V2
        salt_auth = hmac_sha256(shared_secret[:32], salt_enc)
    else:
        salt_auth = hmac_sha256(shared_secret, salt_enc)[:16]
    return salt_enc, salt_auth


salt1 = b"\xa5" * 32
salt2 = b"\x96" * 32
salt3 = b"\x03" * 32
salt4 = b"\x5a" * 16
salt5 = b"\x96" * 64


@pytest.fixture(scope="class")
def MCHmacSecret(
    resetDevice,
):
    req = FidoRequest(extensions={"hmac-secret": True}, options={"rk": True})
    res = resetDevice.sendMC(*req.toMC())
    setattr(res, "request", req)
    return res


@pytest.fixture(scope="class")
def sharedSecret(device, MCHmacSecret):
    return device.client.client_pin._get_shared_secret() + (device.client.client_pin.protocol.VERSION, )


@pytest.fixture(scope="class")
def cipher(device, sharedSecret):
    key_agreement, shared_secret, ver_pin_proto = sharedSecret
    return HmacSecretCipher(shared_secret, ver_pin_proto)


@pytest.fixture(scope="class")
def fixed_users():
    """ Fixed set of users to enable accounts to get overwritten """
    return [generate_user() for i in range(0, 100)]


class TestHmacSecret(object):
    def test_hmac_secret_make_credential(self, MCHmacSecret):
        assert MCHmacSecret.auth_data.extensions
        assert "hmac-secret" in MCHmacSecret.auth_data.extensions
        assert MCHmacSecret.auth_data.extensions["hmac-secret"] == True

    def test_hmac_secret_info(self, info):
        assert "hmac-secret" in info.extensions

    def test_fake_extension(self, device):
        req = FidoRequest(extensions={"tetris": True})
        res = device.sendMC(*req.toMC())

    def test_get_shared_secret(self, sharedSecret):
        pass

    @pytest.mark.parametrize("salts", [(salt1,), (salt1, salt2)])
    def test_hmac_secret_entropy(
        self, device, MCHmacSecret, cipher, sharedSecret, salts
    ):
        key_agreement, shared_secret, ver_pin_proto = sharedSecret
        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, salts)
        req = FidoRequest(
            extensions={"hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth, 4: ver_pin_proto}}
        )
        print("key-agreement", key_agreement)
        auth = device.sendGA(*req.toGA())

        ext = auth.auth_data.extensions
        assert ext
        assert "hmac-secret" in ext
        assert isinstance(ext["hmac-secret"], bytes)
        assert len(ext["hmac-secret"]) == len(salts) * 32 + len(cipher.get_iv())

        verify(MCHmacSecret, auth, req.cdh)

        key = cipher.hs_decrypt(ext["hmac-secret"])

        print(shannon_entropy(ext["hmac-secret"]))
        if len(salts) == 1:
            assert shannon_entropy(ext["hmac-secret"]) > 4.6
            assert shannon_entropy(key) > 4.6
        if len(salts) == 2:
            assert shannon_entropy(ext["hmac-secret"]) > 5.4
            assert shannon_entropy(key) > 5.4

    def get_output(self, device, MCHmacSecret, cipher, sharedSecret, salts):
        key_agreement, shared_secret, ver_pin_proto = sharedSecret
        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, salts)
        req = FidoRequest(
            extensions={"hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth, 4: ver_pin_proto}}
        )
        auth = device.sendGA(*req.toGA())

        ext = auth.auth_data.extensions
        assert ext
        assert "hmac-secret" in ext
        assert isinstance(ext["hmac-secret"], bytes)
        assert len(ext["hmac-secret"]) == len(salts) * 32 + len(cipher.get_iv())

        verify(MCHmacSecret, auth, req.cdh)

        output = cipher.hs_decrypt(ext["hmac-secret"])

        if len(salts) == 2:
            return (output[0:32], output[32:64])
        else:
            return output

    def test_hmac_secret_sanity(self, device, MCHmacSecret, cipher, sharedSecret):
        output1 = self.get_output(device, MCHmacSecret, cipher, sharedSecret, (salt1,))
        output12 = self.get_output(
            device, MCHmacSecret, cipher, sharedSecret, (salt1, salt2)
        )
        output21 = self.get_output(
            device, MCHmacSecret, cipher, sharedSecret, (salt2, salt1)
        )

        assert output12[0] == output1
        assert output21[1] == output1
        assert output21[0] == output12[1]
        assert output12[0] != output12[1]

    def test_missing_keyAgreement(self, device, cipher, sharedSecret):
        key_agreement, shared_secret, ver_pin_proto = sharedSecret

        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, (salt3,))

        req = FidoRequest(extensions={"hmac-secret": {2: salt_enc, 3: salt_auth, 4: ver_pin_proto}})

        with pytest.raises(CtapError):
            device.sendGA(*req.toGA())

    def test_missing_saltAuth(self, device, cipher, sharedSecret):
        key_agreement, shared_secret, ver_pin_proto = sharedSecret

        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, (salt3,))

        req = FidoRequest(extensions={"hmac-secret": {1: key_agreement, 2: salt_enc, 4: ver_pin_proto}})

        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    def test_missing_saltEnc(self, device, cipher, sharedSecret):
        key_agreement, shared_secret, ver_pin_proto = sharedSecret

        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, (salt3,))

        req = FidoRequest(extensions={"hmac-secret": {1: key_agreement, 3: salt_auth, 4: ver_pin_proto}})

        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    def test_bad_auth(self, device, cipher, sharedSecret):

        key_agreement, shared_secret, ver_pin_proto = sharedSecret

        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, (salt3,))

        bad_auth = list(salt_auth[:])
        bad_auth[len(bad_auth) // 2] = bad_auth[len(bad_auth) // 2] ^ 1
        bad_auth = bytes(bad_auth)

        req = FidoRequest(
            extensions={"hmac-secret": {1: key_agreement, 2: salt_enc, 3: bad_auth, 4: ver_pin_proto}}
        )

        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    @pytest.mark.parametrize("salts", [(salt4,), (salt4, salt5)])
    def test_invalid_salt_length(self, device, cipher, sharedSecret, salts):
        key_agreement, shared_secret, ver_pin_proto = sharedSecret
        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, salts)

        req = FidoRequest(
            extensions={"hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth, 4: ver_pin_proto}}
        )

        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code in [ CtapError.ERR.INVALID_LENGTH, CtapError.ERR.INVALID_CBOR ]

    @pytest.mark.parametrize("salts", [(salt1,), (salt1, salt2)])
    def test_get_next_assertion_has_extension(
        self, device, MCHmacSecret, cipher, sharedSecret, salts, fixed_users
    ):
        """ Check that get_next_assertion properly returns extension information for multiple accounts. """
        accounts = 3
        regs = []
        auths = []
        rp = {"id": f"example_salts_{len(salts)}.org", "name": "ExampleRP_2"}

        for i in range(0, accounts):
            req = FidoRequest(
                extensions={"hmac-secret": True},
                options={"rk": True},
                rp=rp,
                user=fixed_users[i],
            )
            res = device.sendMC(*req.toMC())
            regs.append(res)

        key_agreement, shared_secret, ver_pin_proto = sharedSecret
        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, salts)
        req = FidoRequest(
            extensions={"hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth, 4: ver_pin_proto}},
            rp=rp,
        )

        auth = device.sendGA(*req.toGA())
        assert auth.number_of_credentials == accounts

        auths.append(auth)
        for i in range(0, accounts - 1):
            auths.append(device.ctap2.get_next_assertion())

        hmac_keys = {}
        for x in auths:
            assert x.auth_data.flags & (1 << 7)  # has extension
            ext = x.auth_data.extensions
            assert ext
            assert "hmac-secret" in ext
            assert isinstance(ext["hmac-secret"], bytes)
            assert len(ext["hmac-secret"]) == len(salts) * 32 + len(cipher.get_iv())
            key = cipher.hs_decrypt(ext["hmac-secret"])
            hmac_keys[x.credential['id']] = key

        auths.reverse()
        for x, y in zip(regs, auths):
            verify(x, y, req.cdh)

        for cred_id in hmac_keys.keys():
            req1 = FidoRequest(req, allow_list = [{"id": cred_id, "type": "public-key"}])
            auth = device.sendGA(*req1.toGA())
            ext = auth.auth_data.extensions
            key = cipher.hs_decrypt(ext["hmac-secret"])
            assert auth.credential['id'] == cred_id
            assert key == hmac_keys[cred_id]

    def test_hmac_secret_with_other_extensions(
        self, resetDevice, info, cipher, sharedSecret
    ):
        if "credBlob" in info.extensions and \
           "credProtect" in info.extensions and \
           "largeBlobKey" in info.extensions:
           print("Test all 4 extensions")
        else:
            pytest.skip("unsupported extensions")
        blob = b"a" * info.max_cred_blob_length
        req = FidoRequest(extensions={
            "credBlob": blob,
            "credProtect": 1,
            "hmac-secret": True,
            "largeBlobKey": True,
        }, options={"rk": True})
        mcRes = resetDevice.sendMC(*req.toMC())
        setattr(mcRes, "request", req)
        lbk = mcRes.large_blob_key
        ext = mcRes.auth_data.extensions
        assert "hmac-secret" in ext
        assert "credBlob" in ext
        assert "credProtect" in ext

        key_agreement, shared_secret, ver_pin_proto = sharedSecret
        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, (salt1, salt2))
        req = FidoRequest(
            extensions={
                "credBlob": True,
                "hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth, 4: ver_pin_proto},
                "largeBlobKey": True,
            }
        )
        auth = resetDevice.sendGA(*req.toGA())

        assert lbk == auth.large_blob_key
        ext = auth.auth_data.extensions
        assert ext
        assert "hmac-secret" in ext
        assert "credBlob" in ext
        assert ext["credBlob"] == blob

        verify(mcRes, auth, req.cdh)

class TestHmacSecretUV(object):
    def test_hmac_secret_different_with_uv(
        self, device, MCHmacSecret, cipher, sharedSecret
    ):
        salts = [salt1]
        key_agreement, shared_secret, ver_pin_proto = sharedSecret
        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, salts)
        req = FidoRequest(
            extensions={"hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth, 4: ver_pin_proto}}
        )
        auth_no_uv = device.sendGA(*req.toGA())
        assert (auth_no_uv.auth_data.flags & (1 << 2)) == 0

        ext_no_uv = auth_no_uv.auth_data.extensions
        assert ext_no_uv
        assert "hmac-secret" in ext_no_uv
        assert isinstance(ext_no_uv["hmac-secret"], bytes)
        assert len(ext_no_uv["hmac-secret"]) == len(salts) * 32 + len(cipher.get_iv())

        verify(MCHmacSecret, auth_no_uv, req.cdh)

        # Now get same auth with UV
        pin = "1234"
        device.client.client_pin.set_pin(pin)
        pin_token = device.client.client_pin.get_pin_token(pin)
        pin_auth = hmac_sha256(pin_token, req.cdh)[:16]

        req = FidoRequest(
            req,
            pin_protocol=1,
            pin_auth=pin_auth,
            extensions={"hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth, 4: ver_pin_proto}},
        )

        auth_uv = device.sendGA(*req.toGA())
        assert auth_uv.auth_data.flags & (1 << 2)
        ext_uv = auth_uv.auth_data.extensions
        assert ext_uv
        assert "hmac-secret" in ext_uv
        assert isinstance(ext_uv["hmac-secret"], bytes)
        assert len(ext_uv["hmac-secret"]) == len(salts) * 32 + len(cipher.get_iv())

        verify(MCHmacSecret, auth_uv, req.cdh)

        # Now see if the hmac-secrets are different
        assert ext_no_uv["hmac-secret"] != ext_uv["hmac-secret"]
