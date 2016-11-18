#!/usr/bin/env python

import BaseHTTPServer

from ct.crypto.signing import signer_ecdsa
from ct.crypto.v2 import log_issuer
from ct.log.v2.frontend import v2_handler

if __name__ == '__main__':
  server_address = ('', 8000)
  #TODO(eranm): Flag
  signer = signer_ecdsa.EcdsaSigner(
      open("/Users/eranm/code/ct-mine/test/testdata/ct-server-key.pem", "rb").read())
  #TODO(eranm): OID from the unassigned space.
  log_id = "1.2.3"
  issuer = log_issuer.LogIssuer(signer, log_id)
  log_handler = v2_handler.LogHandler(issuer)
  httpd = BaseHTTPServer.HTTPServer(server_address, v2_handler.V2Handler)
  httpd._log_handler = log_handler
  while True:
    print 'Waiting for requests...'
    httpd.handle_request()
