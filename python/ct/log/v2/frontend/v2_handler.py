#!/usr/bin/env python

import binascii
import base64
import BaseHTTPServer
import collections
import simplejson

import ct.crypto.error
from ct.crypto import cert
from ct.serialization import tls_message

def _GenerateErrorArray(error_code, error_message):
  return {'error_code': error_code, 'error_message': error_message}

LogHandlerResponse = collections.namedtuple(
  'LogHandlerResponse', ['success', 'return_data'])

def _ParseJson(json_data):
    if not json_data:
        return (False, "Input missing.")
    try: 
        return (True, simplejson.loads(json_data))
    except simplejson.JSONDecodeError:
        return (False, "Invalid json.")


class LogHandler(object):
    def __init__(self, log_issuer):
        self._log_issuer = log_issuer

    def _AddChain(self, req_data):
        (parsed_ok, decoded_data) = _ParseJson(req_data)

        if not parsed_ok:
            return LogHandlerResponse(
                    False,
                    _GenerateErrorArray("bad chain", "Failed decoding chain json."))

        if 'chain' not in decoded_data:
            return LogHandlerResponse(
                    False,
                    _GenerateErrorArray("bad chain", "chain parameter not found."))

        encoded_certs = decoded_data['chain']
        certs = []
        try:
            for b64_cert in encoded_certs:
                cert_bytes = base64.decodestring(b64_cert)
                certs.append(cert.Certificate.from_der(cert_bytes))
        except binascii.Error as e:
            return LogHandlerResponse(
                    False,
                    _GenerateErrorArray("bad certificate",
                        "Failed to decode a certificate."))
        except ct.crypto.error.ASN1Error:
            return LogHandlerResponse(False,
                    _GenerateErrorArray("bad certificate", "Bad ASN.1"))

        trans_item = self._log_issuer.issue_x509_cert_sct(certs[0], certs[1:])
        return LogHandlerResponse(True, {'sct': base64.b64encode(tls_message.encode(trans_item))})

    def _GetSth(self):
        sth = self._log_issuer.get_sth()
        return LogHandlerResponse(True, {'sth': base64.b64encode(tls_message.encode(sth))})

    def HandleRequest(self, req_endpoint, req_data = None):
        if req_endpoint == 'add-chain':
            return self._AddChain(req_data)
        if req_endpoint == 'get-sth':
            return self._GetSth()
        return LogHandlerResponse(
                False,
                _GenerateErrorArray("not compliant",
                    "Unknown request: %s" % req_endpoint))

def InterpretHandlerResponse(handler_response):
    if handler_response.success:
        return_http_code = 200
    else:
        return_http_code = 400
    return (return_http_code, simplejson.dumps(handler_response.return_data))

class V2Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    _log_prefix = '/ct/v2/'

    def do_GET(self):
        print "Incoming GET request from %s on %s" % (
                self.client_address, self.path)
        (prefix, request) = self.path.split(V2Handler._log_prefix)
        if not request:
            self.send_my_resp(400, simplejson.dumps({"error_code": "not compliant"}))
            return
        res = self.server._log_handler.HandleRequest(request, None)
        self.send_my_resp(*InterpretHandlerResponse(res))

    def do_POST(self):
        print "Incoming POST request from: %s, headers: %s to %s" % (
                self.client_address, self.headers, self.path)
        (prefix, request) = self.path.split(V2Handler._log_prefix)

        if not request:
            self.send_my_resp(400, simplejson.dumps({"error_code": "not compliant"}))
            return

        data_length = None
        for header_name in self.headers.keys():
            if header_name.lower() == "content-length":
                data_length = int(self.headers[header_name])

        if data_length is None:
            self.send_my_resp(400, simplejson.dumps({"error_code": "not compliant"}))
            return

        print 'Data length:',data_length
        read_data = self.rfile.read(data_length)
        print 'Read data: ',read_data

        res = self.server._log_handler.HandleRequest(request, read_data)
        self.send_my_resp(*InterpretHandlerResponse(res))

    def send_my_resp(self, code, message):
        msg_len = len(message)
        self.send_response(code)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-Length", str(msg_len))
        self.end_headers()
        self.wfile.write(message)
