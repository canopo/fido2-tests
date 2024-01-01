from fido2.cose import SM2
from fido2.ctap import CtapError
from tests.utils import *

def test_get_info_algorithms(info):
    print(info.algorithms)
    assert {'alg': -48, 'type': 'public-key'} in info.algorithms

def test_sm2(device):
    mc_req = FidoRequest(
        key_params=[{"type": "public-key", "alg": SM2.ALGORITHM}]
    )
    try:
        mc_res = device.sendMC(*mc_req.toMC())
    except CtapError as e:
        if e.code == CtapError.ERR.UNSUPPORTED_ALGORITHM:
            print("SM2 is not supported.  Skip this test.")
            return

    setattr(mc_res, "request", mc_req)

    allow_list = [
        {
            "id": mc_res.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }
    ]

    ga_req = FidoRequest(allow_list=allow_list)
    ga_res = device.sendGA(*ga_req.toGA())
    setattr(ga_res, "request", ga_req)

    try:
        verify(mc_res, ga_res)
    except:
        # Print out extra details on failure
        from binascii import hexlify

        print("authdata", hexlify(ga_res.auth_data))
        print("cdh", hexlify(ga_res.request.cdh))
        print("sig", hexlify(ga_res.signature))
