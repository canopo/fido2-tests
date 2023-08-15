import pytest
from fido2.ctap import CtapError

from tests.utils import FidoRequest, verify

class TestSelection(object):
    def test_authenticator_selection(self, device):
        device.ctap2.selection()
