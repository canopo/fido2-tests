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
def MC_RK_Res(device, PinToken):
    results = []
    req = FidoRequest()
    rp = {"id": "ssh:", "name": "Bate Goiko"}
    req = FidoRequest(
        request=None,
        pin=PIN,
        rp=rp,
        options={"rk": True},
    )
    res = device.sendMC(*req.toMC())
    setattr(res, "request", req)
    results.append(res)

    req = FidoRequest()
    rp = {"id": "xakcop.com", "name": "John Doe"}
    req = FidoRequest(
        request=None,
        pin=PIN,
        rp=rp,
        options={"rk": True},
    )
    res = device.sendMC(*req.toMC())
    setattr(res, "request", req)
    results.append(res)
    return results

@pytest.fixture(scope = 'function')
def CredMgmt(device, PinToken):
    pin_protocol = PinProtocolV1()
    return CredentialManagement(device.ctap2, pin_protocol, _get_pin_token_with_CM_permission(device))


def _test_enumeration(CredMgmt, rp_map):
    "Enumerate credentials using BFS"
    res = CredMgmt.enumerate_rps()
    assert len(rp_map.keys()) == len(res)

    for rp in res:
        creds = CredMgmt.enumerate_creds(sha256(rp[3]["id"].encode("utf8")))
        assert len(creds) == rp_map[rp[3]["id"]]


def _test_enumeration_interleaved(CredMgmt, rp_map):
    "Enumerate credentials using DFS"
    first_rp = CredMgmt.enumerate_rps_begin()
    assert len(rp_map.keys()) == first_rp[CredentialManagement.RESULT.TOTAL_RPS]

    rk_count = 1
    first_rk = CredMgmt.enumerate_creds_begin(sha256(first_rp[3]["id"].encode("utf8")))
    for i in range(1, first_rk[CredentialManagement.RESULT.TOTAL_CREDENTIALS]):
        c = CredMgmt.enumerate_creds_next()
        rk_count += 1

    assert rk_count == rp_map[first_rp[3]["id"]]

    for i in range(1, first_rp[CredentialManagement.RESULT.TOTAL_RPS]):
        next_rp = CredMgmt.enumerate_rps_next()

        rk_count = 1
        first_rk = CredMgmt.enumerate_creds_begin(
            sha256(next_rp[3]["id"].encode("utf8"))
        )
        for i in range(1, first_rk[CredentialManagement.RESULT.TOTAL_CREDENTIALS]):
            c = CredMgmt.enumerate_creds_next()
            rk_count += 1

        assert rk_count == rp_map[next_rp[3]["id"]]


def CredMgmtWrongPinAuth(device, pin_token):
    pin_protocol = PinProtocolV1()
    wrong_pt = bytearray(pin_token)
    wrong_pt[0] = (wrong_pt[0] + 1) % 256
    return CredentialManagement(device.ctap2, pin_protocol, bytes(wrong_pt))


def assert_cred_response_has_all_fields(cred_res):
    for i in (
        CredentialManagement.RESULT.USER,
        CredentialManagement.RESULT.CREDENTIAL_ID,
        CredentialManagement.RESULT.PUBLIC_KEY,
        CredentialManagement.RESULT.TOTAL_CREDENTIALS,
        CredentialManagement.RESULT.CRED_PROTECT,
    ):
        assert i in cred_res

def assert_all_fields_of_cred_is_correct(cred_res, mc_req, mc_res):
    FID = CredentialManagement.RESULT
    assert cred_res[FID.USER]['id'] == mc_req.user['id']
    assert cred_res[FID.USER]['name'] == mc_req.user['name']
    assert cred_res[FID.USER]['displayName'] == mc_req.user['displayName']
    assert cred_res[FID.CREDENTIAL_ID]['id'] == mc_res.auth_data.credential_data.credential_id[:]
    assert cred_res[FID.CREDENTIAL_ID]['type'] == 'public-key'
    assert cred_res[FID.PUBLIC_KEY] == mc_res.auth_data.credential_data.public_key
    assert cred_res[FID.CRED_PROTECT] == mc_req.extensions['credProtect'] if \
        (mc_req.extensions and 'credProtect' in mc_req.extensions) else 1
    if mc_res.large_blob_key:
        assert cred_res[FID.LARGE_BLOB_KEY] == mc_res.large_blob_key

class TestCredentialManagement(object):
    def test_get_info(self, info):
        assert "credMgmt" in info.options
        assert info.options["credMgmt"] == True
        print(info)
        assert 0x7 in info
        assert info[0x7] > 1
        assert 0x8 in info
        assert info[0x8] > 1

    def test_get_metadata(self, MC_RK_Res, CredMgmt):
        metadata = CredMgmt.get_metadata()
        assert metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 2
        assert metadata[CredentialManagement.RESULT.MAX_REMAINING_COUNT] >= 48

    def test_enumerate_rps(self, MC_RK_Res, CredMgmt):
        res = CredMgmt.enumerate_rps()
        print(res)
        assert len(res) == 2
        assert res[0][CredentialManagement.RESULT.RP]["id"] == "ssh:"
        assert res[0][CredentialManagement.RESULT.RP_ID_HASH] == sha256(b"ssh:")
        # Solo doesn't store rpId with the exception of "ssh:"
        assert res[1][CredentialManagement.RESULT.RP]["id"] == "xakcop.com"
        assert res[1][CredentialManagement.RESULT.RP_ID_HASH] == sha256(b"xakcop.com")

    def test_enumarate_creds(self, MC_RK_Res, CredMgmt):
        res = CredMgmt.enumerate_creds(sha256(b"ssh:"))
        assert len(res) == 1
        assert_cred_response_has_all_fields(res[0])
        res = CredMgmt.enumerate_creds(sha256(b"xakcop.com"))
        assert len(res) == 1
        assert_cred_response_has_all_fields(res[0])
        res = CredMgmt.enumerate_creds(sha256(b"missing.com"))
        assert not res

    def test_get_metadata_wrong_pinauth(self, device, MC_RK_Res, PinToken):
        cmd = lambda credMgmt: credMgmt.get_metadata()
        self._test_wrong_pinauth(device, cmd, PinToken)

    def test_rpbegin_wrong_pinauth(self, device, MC_RK_Res, PinToken):
        cmd = lambda credMgmt: credMgmt.enumerate_rps_begin()
        self._test_wrong_pinauth(device, cmd, PinToken)

    def test_rkbegin_wrong_pinauth(self, device, MC_RK_Res, PinToken):
        cmd = lambda credMgmt: credMgmt.enumerate_creds_begin(sha256(b"ssh:"))
        self._test_wrong_pinauth(device, cmd, PinToken)

    def test_rpnext_without_rpbegin(self, device, MC_RK_Res, CredMgmt):
        CredMgmt.enumerate_creds_begin(sha256(b"ssh:"))
        with pytest.raises(CtapError) as e:
            CredMgmt.enumerate_rps_next()
        assert e.value.code == CtapError.ERR.NOT_ALLOWED

    def test_rknext_without_rkbegin(self, device, MC_RK_Res, CredMgmt):
        CredMgmt.enumerate_rps_begin()
        with pytest.raises(CtapError) as e:
            CredMgmt.enumerate_creds_next()
        assert e.value.code == CtapError.ERR.NOT_ALLOWED

    def test_delete(self, device, PinToken, CredMgmt):

        # create a new RK
        rp = {"id": "example_3.com", "name": "John Doe 2"}
        req = FidoRequest(
            pin=PIN,
            options={"rk": True},
            rp=rp,
        )
        reg = device.sendMC(*req.toMC())

        # make sure it works
        req = FidoRequest(rp=rp)
        auth = device.sendGA(*req.toGA())

        verify(reg, auth, req.cdh)

        CredMgmt.pin_uv_token = _get_pin_token_with_CM_permission(device)

        # get the ID from enumeration
        creds = CredMgmt.enumerate_creds(reg.auth_data.rp_id_hash)
        for cred in creds:
            if cred[7]["id"] == reg.auth_data.credential_data.credential_id:
                break

        # delete it
        cred = {"id": cred[7]["id"], "type": "public-key"}
        CredMgmt.delete_cred(cred)

        # make sure it doesn't work
        req = FidoRequest(rp=rp)
        with pytest.raises(CtapError) as e:
            auth = device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

        req.allow_list = [{
            "id": reg.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }]
        with pytest.raises(CtapError) as e:
            auth = device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    def test_add_delete(self, device, PinToken, CredMgmt):
        """ Delete a credential in the 'middle' and ensure other credentials are not affected. """

        rp = {"id": "example_4.com", "name": "John Doe 3"}
        regs = []

        # create 3 new RK's
        for i in range(0, 3):
            req = FidoRequest(
                pin=PIN,
                options={"rk": True},
                rp=rp,
            )
            reg = device.sendMC(*req.toMC())
            regs.append(reg)
            print("CREATE:", hexlify(reg.auth_data.credential_data.credential_id))

        CredMgmt.pin_uv_token = _get_pin_token_with_CM_permission(device)

        # Check they all enumerate
        res = CredMgmt.enumerate_creds(regs[1].auth_data.rp_id_hash)
        assert len(res) == 3

        # delete the middle one
        creds = CredMgmt.enumerate_creds(reg.auth_data.rp_id_hash)
        for cred in creds:
            print("CHECK: ", hexlify(cred[7]["id"]))
            if cred[7]["id"] == regs[1].auth_data.credential_data.credential_id:
                break

        assert cred[7]["id"] == regs[1].auth_data.credential_data.credential_id

        cred = {"id": cred[7]["id"], "type": "public-key"}
        CredMgmt.delete_cred(cred)

        # Check one less enumerates
        res = CredMgmt.enumerate_creds(regs[0].auth_data.rp_id_hash)
        assert len(res) == 2

    def test_interleaved_add_delete(self, device, PinToken, CredMgmt):
        RPs = [{"id": "new_rp1.com"}, {"id": "new_rp2.com"}, {"id": "new_rp3.com"}]
        reg = None
        regs = {}
        for op_num in range(1000):
            r = random.randint(1, 100)
            thres = 50 if op_num < 20 else 80
            if r < thres or len(regs) == 0:
                rp = random.choice(RPs)
                req = FidoRequest(
                    pin=PIN,
                    options={"rk": True},
                    rp=rp,
                )
                try:
                    reg = device.sendMC(*req.toMC())
                    regs[reg.auth_data.credential_data.credential_id] = req.user['id']
                    print("CREATE: ", hexlify(reg.auth_data.credential_data.credential_id))
                except CtapError as err:
                    assert err.code == CtapError.ERR.KEY_STORE_FULL
                    break
            else:
                to_be_del = random.choice(list(regs.keys()))
                print("DELETE: ", hexlify(to_be_del))
                cred = {"id": to_be_del, "type": "public-key"}
                CredMgmt.pin_uv_token = _get_pin_token_with_CM_permission(device)
                CredMgmt.delete_cred(cred)
                del regs[to_be_del]

        # Now the storage must be full
        with pytest.raises(CtapError) as e:
            req = FidoRequest(
                pin=PIN,
                options={"rk": True},
                rp=rp,
            )
            device.sendMC(*req.toMC())
        assert e.value.code == CtapError.ERR.KEY_STORE_FULL

        CredMgmt.pin_uv_token = _get_pin_token_with_CM_permission(device)

        for rp in RPs:
            rp_id_hash = sha256(rp['id'].encode('ascii'))
            # Check them all
            creds = CredMgmt.enumerate_creds(rp_id_hash)
            for cred in creds:
                cred_id = cred[7]["id"]
                user_id = cred[6]["id"]
                print("CHECK: ", hexlify(cred_id))
                assert cred_id in regs
                assert user_id == regs[cred_id]
                del regs[cred_id]

        for cred_id in regs.keys():
            print("ERR! NOT RETURN: ", hexlify(cred_id))
        assert len(regs) == 0

    def test_delete_with_rpid(self, device, PinToken, CredMgmt):
        # create a new RK
        rp = {"id": "example_3.com", "name": "John Doe 2"}
        req = FidoRequest(
            pin=PIN,
            options={"rk": True},
            rp=rp,
        )
        reg = device.sendMC(*req.toMC())

        CredMgmt.pin_uv_token = device.sendPP(PIN, 
            permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT, 
            permissions_rpid=rp['id'])

        # get the ID from enumeration
        creds = CredMgmt.enumerate_creds(reg.auth_data.rp_id_hash)
        for cred in creds:
            if cred[7]["id"] == reg.auth_data.credential_data.credential_id:
                break

        # delete it
        cred = {"id": cred[7]["id"], "type": "public-key"}
        CredMgmt.delete_cred(cred)

        # make sure it doesn't work
        req = FidoRequest(rp=rp)
        with pytest.raises(CtapError) as e:
            auth = device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

        # delete it again
        with pytest.raises(CtapError) as e:
            CredMgmt.delete_cred(cred)
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    def test_missing_param(self, device, PinToken):
        for cmd in range(1, 8):

            if cmd == CredentialManagement.CMD.ENUMERATE_CREDS_BEGIN or \
                cmd == CredentialManagement.CMD.DELETE_CREDENTIAL or \
                cmd == CredentialManagement.CMD.UPDATE_USER_INFO:
                # Missing subCommandParams
                with pytest.raises(CtapError) as e:
                    device.ctap2.credential_mgmt(cmd, pin_uv_protocol=1, pin_uv_param=32*b'U')
                assert e.value.code == CtapError.ERR.MISSING_PARAMETER

            if cmd != CredentialManagement.CMD.ENUMERATE_RPS_NEXT and \
                cmd != CredentialManagement.CMD.ENUMERATE_CREDS_NEXT:
                with pytest.raises(CtapError) as e:
                    device.ctap2.credential_mgmt(cmd)
                assert e.value.code == CtapError.ERR.PUAT_REQUIRED

                # Missing pinUvAuthProtocol
                with pytest.raises(CtapError) as e:
                    device.ctap2.credential_mgmt(cmd, sub_cmd_params={}, pin_uv_param=32*b'U')
                assert e.value.code == CtapError.ERR.MISSING_PARAMETER

                with pytest.raises(CtapError) as e:
                    device.ctap2.credential_mgmt(cmd, sub_cmd_params={}, pin_uv_protocol=-1, pin_uv_param=32*b'U')
                assert e.value.code == CtapError.ERR.INVALID_PARAMETER

    @pytest.mark.parametrize(
        "perm", [None, ClientPin.PERMISSION.LARGE_BLOB_WRITE, ClientPin.PERMISSION.CREDENTIAL_MGMT]
    )
    @pytest.mark.parametrize(
        "withRpID", [True, False]
    )
    def test_permission_check(self, perm, withRpID, device, MC_RK_Res, PinToken, CredMgmt):
        rpid = "example.com" if withRpID else None
        CredMgmt.pin_uv_token = device.sendPP(PIN, permissions=perm, permissions_rpid=rpid)

        # delete_cred must be the last one
        for method in (CredMgmt.get_metadata, CredMgmt.enumerate_rps, CredMgmt.enumerate_creds_begin, CredMgmt.update_user_info, CredMgmt.delete_cred):
            kwargs = {}
            if method == CredMgmt.enumerate_creds_begin:
                kwargs['rp_id_hash'] = MC_RK_Res[0].auth_data.rp_id_hash
            elif method == CredMgmt.delete_cred or method == CredMgmt.update_user_info:
                kwargs['cred_id'] = {"id": MC_RK_Res[0].auth_data.credential_data.credential_id, "type": "public-key"}
                if method == CredMgmt.update_user_info:
                    kwargs['user_info'] = {"id": MC_RK_Res[0].request.user['id']}
            if perm == ClientPin.PERMISSION.CREDENTIAL_MGMT and not withRpID:
                method(**kwargs)
            else:
                with pytest.raises(CtapError) as e:
                    method(**kwargs)
                assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    @pytest.mark.parametrize(
        "withRpID", [True, False]
    )
    def test_update_user_info(self, withRpID, device, MC_RK_Res, PinToken, CredMgmt):
        rpid = MC_RK_Res[0].request.rp['id'] if withRpID else None
        CredMgmt.pin_uv_token = device.sendPP(PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT, permissions_rpid=rpid)

        cred = {"id": MC_RK_Res[0].auth_data.credential_data.credential_id, "type": "public-key"}
        user_info = generate_user()
        del user_info['icon']
        user_info['id'] = MC_RK_Res[0].request.user['id']
        CredMgmt.update_user_info(cred, user_info)

        ret_creds = CredMgmt.enumerate_creds(MC_RK_Res[0].auth_data.rp_id_hash)
        assert len(ret_creds) == 1
        assert ret_creds[0][6] == user_info

        user_info['id'] = b'invalid uid'
        with pytest.raises(CtapError) as e:
            CredMgmt.update_user_info(cred, user_info)
        assert e.value.code == CtapError.ERR.INVALID_PARAMETER

        # delete it
        CredMgmt.delete_cred(cred)

        with pytest.raises(CtapError) as e:
            CredMgmt.update_user_info(cred, user_info)
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    def test_eddsa_enumerate(self, device, PinToken, MC_RK_Res, CredMgmt):
        rpId = "EdDSA.com"
        mc_req = FidoRequest(
            pin=PIN,
            options={"rk": True},
            rp={"id": rpId},
            key_params=[{"type": "public-key", "alg": EdDSA.ALGORITHM}]
        )
        try:
            mc_res = device.sendMC(*mc_req.toMC())
        except CtapError as e:
            if e.code == CtapError.ERR.UNSUPPORTED_ALGORITHM:
                print("ed25519 is not supported.  Skip this test.")
                return

        CredMgmt.pin_uv_token = device.sendPP(PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        res = CredMgmt.enumerate_creds(sha256(rpId.encode('ascii')))
        assert len(res) == 1
        assert_all_fields_of_cred_is_correct(res[0], mc_req, mc_res)

    def test_fields_of_cred_enumerate(self, device, info, PinToken, CredMgmt):
        for credProtectVal in (None, 1, 2, 3):
            for withLB in (False, True):
                extensions = {}
                if (credProtectVal is not None) and ('credProtect' in info.extensions):
                    extensions['credProtect'] = credProtectVal
                if withLB and ('largeBlobKey' in info.extensions):
                    extensions['largeBlobKey'] = True
                mc_req = FidoRequest(
                    pin=PIN,
                    options={"rk": True},
                    extensions=extensions
                )
                mc_res = device.sendMC(*mc_req.toMC())
                CredMgmt.pin_uv_token = device.sendPP(PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
                creds = CredMgmt.enumerate_creds(sha256(mc_req.rp['id'].encode('ascii')))
                for cred in creds:
                    if cred[7]['id'] == mc_res.auth_data.credential_data.credential_id[:]:
                        assert_all_fields_of_cred_is_correct(cred, mc_req, mc_res)
                        break
                else:
                    raise ValueError("Credential not in response")


    def test_multiple_creds_per_multiple_rps(
        self, device, PinToken, MC_RK_Res, CredMgmt
    ):
        res = CredMgmt.enumerate_rps()
        assert len(res) == 2

        new_rps = [
            {"id": "new_example_1.com", "name": "Example-3-creds"},
            {"id": "new_example_2.com", "name": "Example-3-creds"},
            {"id": "new_example_3.com", "name": "Example-3-creds"},
        ]

        # create 3 new credentials per RP
        for rp in new_rps:
            for i in range(0, 3):
                req = FidoRequest(
                    pin=PIN,
                    options={"rk": True},
                    rp=rp,
                )
                reg = device.sendMC(*req.toMC())

        CredMgmt.pin_uv_token = _get_pin_token_with_CM_permission(device)

        res = CredMgmt.enumerate_rps()
        assert len(res) == 5

        for rp in res:
            if rp[3]["id"][:12] == "new_example_":
                creds = CredMgmt.enumerate_creds(sha256(rp[3]["id"].encode("utf8")))
                assert len(creds) == 3

    @pytest.mark.parametrize(
        "enumeration_test", [_test_enumeration, ] # _test_enumeration_interleaved
    )
    def test_multiple_enumeration(
        self, device, PinToken, MC_RK_Res, CredMgmt, enumeration_test
    ):
        """ Test enumerate still works after different commands """

        res = CredMgmt.enumerate_rps()

        expected_enumeration = {"xakcop.com": 1, "ssh:": 1}

        enumeration_test(CredMgmt, expected_enumeration)

        new_rps = [
            {"id": "example-2.com", "name": "Example-2-creds", "count": 2},
            {"id": "example-1.com", "name": "Example-1-creds", "count": 1},
            {"id": "example-5.com", "name": "Example-5-creds", "count": 5},
        ]

        # create 3 new credentials per RP
        for rp in new_rps:
            for i in range(0, rp["count"]):
                req = FidoRequest(
                    pin=PIN,
                    options={"rk": True},
                    rp={"id": rp["id"], "name": rp["name"]},
                )
                reg = device.sendMC(*req.toMC())

            # Now expect creds from this RP
            expected_enumeration[rp["id"]] = rp["count"]

        CredMgmt.pin_uv_token = _get_pin_token_with_CM_permission(device)

        enumeration_test(CredMgmt, expected_enumeration)
        enumeration_test(CredMgmt, expected_enumeration)

        metadata = CredMgmt.get_metadata()

        enumeration_test(CredMgmt, expected_enumeration)
        enumeration_test(CredMgmt, expected_enumeration)

    @pytest.mark.parametrize(
        "enumeration_test", [_test_enumeration, ] # _test_enumeration_interleaved
    )
    def test_multiple_enumeration_with_deletions(
        self, device, PinToken, MC_RK_Res, CredMgmt, enumeration_test
    ):
        """ Create each credential in random order.  Test enumerate still works after randomly deleting each credential"""

        res = CredMgmt.enumerate_rps()

        expected_enumeration = {"xakcop.com": 1, "ssh:": 1}

        enumeration_test(CredMgmt, expected_enumeration)

        new_rps = [
            {"id": "example-1.com", "name": "Example-1-creds", "count": 1},
            {"id": "example-2.com", "name": "Example-2-creds", "count": 2},
            {"id": "example-3.com", "name": "Example-3-creds", "count": 3},
        ]

        reg_requests = []

        # create new credentials per RP in random order
        for rp in new_rps:
            for i in range(0, rp["count"]):
                req = FidoRequest(
                    pin=PIN,
                    options={"rk": True},
                    rp={"id": rp["id"], "name": rp["name"]},
                    user=generate_user_maximum(),
                )
                reg_requests.append(req)

        while len(reg_requests):
            req = random.choice(reg_requests)
            reg_requests.remove(req)
            device.sendMC(*req.toMC())

            if req.rp["id"] not in expected_enumeration:
                expected_enumeration[req.rp["id"]] = 1
            else:
                expected_enumeration[req.rp["id"]] += 1

            CredMgmt.pin_uv_token = _get_pin_token_with_CM_permission(device)

            enumeration_test(CredMgmt, expected_enumeration)

        total_creds = len(reg_requests)

        while total_creds != 0:
            rp = random.choice(list(expected_enumeration.keys()))

            num = expected_enumeration[rp]

            index = 0 if num == 1 else random.randint(0, num - 1)
            cred = CredMgmt.enumerate_creds(sha256(rp.encode("utf8")))[index]

            # print('Delete %d index (%d total) cred of %s' % (index, expected_enumeration[rp], rp))
            CredMgmt.delete_cred({"id": cred[7]["id"], "type": "public-key"})

            expected_enumeration[rp] -= 1
            if expected_enumeration[rp] == 0:
                del expected_enumeration[rp]

            if len(list(expected_enumeration.keys())) == 0:
                break

            enumeration_test(CredMgmt, expected_enumeration)

    def _test_wrong_pinauth(self, device, cmd, PinToken):

        credMgmt = CredMgmtWrongPinAuth(device, PinToken)

        for i in range(2):
            with pytest.raises(CtapError) as e:
                cmd(credMgmt)
            assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID
        return

        with pytest.raises(CtapError) as e:
            cmd(credMgmt)
        assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED

        device.reboot()
        credMgmt = CredMgmtWrongPinAuth(device, PinToken)

        for i in range(2):
            time.sleep(0.2)
            with pytest.raises(CtapError) as e:
                cmd(credMgmt)
            assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        with pytest.raises(CtapError) as e:
            cmd(credMgmt)
        assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED

        device.reboot()
        credMgmt = CredMgmtWrongPinAuth(device, PinToken)

        for i in range(1):
            time.sleep(0.2)
            with pytest.raises(CtapError) as e:
                cmd(credMgmt)
            assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        with pytest.raises(CtapError) as e:
            cmd(credMgmt)
        assert e.value.code == CtapError.ERR.PIN_BLOCKED


