from ct.crypto.asn1 import oid
from ct.crypto import merkle
from ct.serialization import tls_message
from ct.proto import client_v2_pb2

import time

def _extract_issuer_key_hash(issuer_cert):
  return issuer_cert.key_hash(hashfunc="sha256")

def _create_x509_entrydata(leaf_cert, certificate_chain):
  #TODO(eranm): Only makes sense of this is a root.
  if len(certificate_chain) == 0:
    issuer_cert = leaf_cert
  else:
    issuer_cert = certificate_chain[0]

  issuer_key_hash = _extract_issuer_key_hash(issuer_cert)
  ts_entry_data = client_v2_pb2.TimestampedCertificateEntryDataV2()
  ts_entry_data.timestamp = int(time.time() * 1000)
  ts_entry_data.issuer_key_hash = issuer_key_hash
  ts_entry_data.tbs_certificate = leaf_cert.get_tbscertificate().encode();
  return ts_entry_data

def _log_id_string_to_oid_bytes(log_id_string):
  o = oid.ObjectIdentifier(log_id_string)
  return o.encode()[1:]


class LogIssuer(object):
  """Produces SCTs."""

  def __init__(self, signer, log_id):
    """Creates an issuer that uses the provided signer.

      Args:
      - signer: an object with sign(data) method that produces deterministic
        signatures.
    """
    self.__signer = signer
    self.__log_id = client_v2_pb2.LogIDV2()
    self.__log_id.log_id = _log_id_string_to_oid_bytes(log_id)
    self.__hasher = merkle.TreeHasher()
    self.__entries = []


  def issue_x509_cert_sct(self, leaf_cert, certificate_chain):
    ts_entry_data = _create_x509_entrydata(leaf_cert, certificate_chain)
    x509_sct = client_v2_pb2.SignedCertificateTimestampDataV2()
    x509_sct.id.MergeFrom(self.__log_id)
    x509_sct.timestamp = ts_entry_data.timestamp
    x509_sct.extensions.MergeFrom(ts_entry_data.sct_extensions)

    trans_item_for_ts_entry = client_v2_pb2.TransItem()
    trans_item_for_ts_entry.versioned_type = client_v2_pb2.X509_ENTRY_V2
    trans_item_for_ts_entry.x509_entry_v2.CopyFrom(ts_entry_data)
    signed_data = self.__signer.sign(tls_message.encode(trans_item_for_ts_entry))
    x509_sct.signature.CopyFrom(signed_data)

    trans_item_for_sct = client_v2_pb2.TransItem()
    trans_item_for_sct.versioned_type = client_v2_pb2.X509_SCT_V2
    trans_item_for_sct.x509_sct_v2.CopyFrom(x509_sct)
    # Add entry to __entries
    self.__entries.append(trans_item_for_ts_entry)

    return trans_item_for_sct

  def get_sth(self):
    # Calculate hash of the root.
    leaves = [tls_message.encode(t) for t in self.__entries]
    root_hash = self.__hasher.hash_full_tree(leaves)

    # Put it in a TreeHeadDataV2 for signature (section 5.7.)
    tree_head_data = client_v2_pb2.TreeHeadDataV2()
    tree_head_data.timestamp = int(time.time() * 1000)
    tree_head_data.tree_size = len(leaves)
    tree_head_data.root_hash = root_hash
    print 'TreeHeadDataV2:', tree_head_data
    # Generate signature over TreeHeadDataV2 (Section 5.8.)
    sth_signature = self.__signer.sign(tls_message.encode(tree_head_data))
    # Put it in a SignedTreeHeadDataV2
    sth = client_v2_pb2.SignedTreeHeadDataV2()
    sth.log_id.MergeFrom(self.__log_id)
    sth.tree_head.CopyFrom(tree_head_data)
    sth.signature.CopyFrom(sth_signature)

    # Put the SignedTreeHeadDataV2 in a TransItem
    trans_item_sth = client_v2_pb2.TransItem()
    trans_item_sth.versioned_type = client_v2_pb2.SIGNED_TREE_HEAD_V2
    trans_item_sth.signed_tree_head_v2.CopyFrom(sth)
    print 'Issued STH: ', trans_item_sth
    return trans_item_sth


