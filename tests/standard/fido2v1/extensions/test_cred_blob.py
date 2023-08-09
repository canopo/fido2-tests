import os
import pytest

from fido2.ctap import CtapError
from tests.utils import *


@pytest.fixture(scope="class")
def ReqWithCredBlob(
    resetDevice,
):
    rp = {"id": f"ReqWithCredBlob", "name": "ExampleRP_1"}
    req = FidoRequest(options={'rk': False}, rp=rp, extensions={"credBlob": b"a"})
    return req

@pytest.fixture(scope="class")
def ReqDcWithCredBlob(
    resetDevice,
):
    rp = {"id": f"ReqDcWithCredBlob", "name": "ExampleRP_2"}
    req = FidoRequest(options={'rk': True}, rp=rp, extensions={"credBlob": b"a"})
    return req


class TestCredBlob(object):
    def test_get_info(self, info):
        print(info)
        assert "FIDO_2_1" in info.versions
        assert "credBlob" in info.extensions
        assert "credProtect" in info.extensions
        # maxCredBlobLength
        assert info.max_cred_blob_length is not None
        assert info.max_cred_blob_length >= 32

    @pytest.mark.parametrize(
        "credBlobLength", [0, 1, 32, -2, -1]
    )
    def test_credblob_make_discoverable_credential(self, device, info, ReqDcWithCredBlob, credBlobLength):
        if credBlobLength < 0:
            credBlobLength += 2
            credBlobLength += info.max_cred_blob_length
        print("building a credBlob, len =", credBlobLength)
        validBlob = (credBlobLength <= info.max_cred_blob_length)
        blob = os.urandom(credBlobLength)

        ReqDcWithCredBlob.extensions["credBlob"] = blob
        res = device.sendMC(*ReqDcWithCredBlob.toMC())
        
        assert res.auth_data.extensions
        assert "credBlob" in res.auth_data.extensions
        assert res.auth_data.extensions["credBlob"] == validBlob

        req = FidoRequest(ReqDcWithCredBlob, options={"up": True}, extensions={"credBlob": True})

        auth = device.sendGA(*req.toGA())
        ext = auth.auth_data.extensions
        assert ext
        assert "credBlob" in ext
        assert isinstance(ext["credBlob"], bytes)
        assert ext["credBlob"] == (b'' if not validBlob else blob)

    def test_credblob_make_credential(self, device, info, ReqWithCredBlob):
        res = device.sendMC(*ReqWithCredBlob.toMC())
        
        assert res.auth_data.extensions
        assert "credBlob" in res.auth_data.extensions

        req = FidoRequest(ReqWithCredBlob, allow_list=[{
                    "id": res.auth_data.credential_data.credential_id[:],
                    "type": "public-key",
                }],
                options={"up": True},
                extensions={"credBlob": True})

        auth = device.sendGA(*req.toGA())
        ext = auth.auth_data.extensions
        assert ext
        assert "credBlob" in ext
        assert isinstance(ext["credBlob"], bytes)

        if res.auth_data.extensions["credBlob"]:
            assert ext["credBlob"] == ReqWithCredBlob.extensions["credBlob"]
        else:
            assert ext["credBlob"] == b''
