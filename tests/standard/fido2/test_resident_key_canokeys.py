import sys
import pytest
from fido2.ctap import CtapError

from tests.utils import *

class TestResidentKeyMaximum(object):
    def test_rk_maximum_list_capacity(self, device):
        """
        Test maximum capacity of resident keys.
        """
        RK_CAPACITY = 64
        device.reset()
        req = FidoRequest(options={"rk": True})

        regs = []
        for i in range(RK_CAPACITY):
            req = FidoRequest(req, user=generate_user_maximum())
            res = device.sendMC(*req.toMC())
            setattr(res, "request", req)
            regs.append(res)

        req = FidoRequest(req, user=generate_user_maximum())
        with pytest.raises(CtapError) as e:
            res = device.sendMC(*req.toMC())
        assert e.value.code == CtapError.ERR.KEY_STORE_FULL
