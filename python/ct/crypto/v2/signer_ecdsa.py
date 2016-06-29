from ct.crypto import error
from ct.crypto import pem
from ct.crypto.asn1 import types
from ct.proto import client_pb2

import hashlib
import ecdsa

class EcdsaSigner(object):
  """Signs using ECDSA signatures."""

  def __init__(self, key_pem):
    """Creates a signer from the a PEM-encoded ECDSA public key.

      Args:
      - key_pem: key.
    """
    self.__key = ecdsa.SigningKey.from_pem(key_pem)

  def sign(self, data_to_sign):
    return self.__key.sign_deterministic(data_to_sign, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)
    #return self.__key.sign(data_to_sign, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)

