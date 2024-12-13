#!/usr/bin/python3

"""
HTTP server that can be upgraded to a WebSocket connection.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

For WebSocket protocol, see IETF RFC 6455.
"""

from __future__ import print_function

from http.server import HTTPServer, BaseHTTPRequestHandler
import os, sys, time, json, struct, hashlib, base64, errno, select
import ssl


# we expect clients to have at least a regular watchdog
session_timeout = 5.0    # close session if not heard from client


class WebSocketTimedOut(Exception):
    pass


class WebSocketRequestHandler(BaseHTTPRequestHandler):
    """
    Handle a single HTTP request that arrives at the server.

    If this request is converted to a websocket stream, the object will
    persist for the duration of the remote session (see handle_ws_loop),
    effectively becoming a session object.
    """
    def do_GET(self):
        self.log_level = 1
        self.t_last_log = None
        self.log("GET '%s': close_connection=%s" % (self.path, self.close_connection))
        if self.path == "/ws":
            key = self.headers.get("Sec-WebSocket-Key")
            hash = hashlib.sha1(key.encode() + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
            exts = self.headers.get("Sec-WebSocket-Extensions", "")
            self.send_response(101)     # "switching protocols"
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", base64.b64encode(hash).decode())
            self.end_headers()
            self.close_connection = False            # will be set to True by our own close handler
            self.log("WS: opened (exts=%s); sent WebSocket acceptance" % (exts))
            self.ws_connection = True
            self.t_start_ws = time.time()
            self.on_ws_start()
            if True:
                # Disable read-buffering.
                # This appears to be necessary, otherwise we read the
                # first 2 bytes of a WS message and then delay for nearly
                # a second trying to read the next 4 bytes.
                # Following solution arrived at by trial and error.
                self.rfile = self.rfile.detach()     # turn the io.BufferedReader into a socket.SocketIO
                #self.rfile.setblocking(False)
                os.set_blocking(self.rfile.fileno(), False)
            self.handle_ws_loop()
        elif self.is_http_prefetch():
            self.send_error(425)    # "Too Early": don't want to replay
        else:
            self.on_get_file()

    def on_get_file(self):
        # Default implementation
        if self.path == "/" or self.path == "index.html":
            self.send_response(200, "")
            self.end_headers()
            self.wfile.write(b"<html><head><title>websocket</title></head><body>test</body></html>")
        else:
            self.send_error(404)

    def is_http_prefetch(self):
        sp = self.headers.get("Sec-Purpose")
        return sp is not None and "prefetch" in sp.split(';')

    def handle_ws_loop(self):
        # Loop doing blocking reads on the websocket descriptor, until the
        # other end closes the session.
        # What we really want is to multiplex the websocket activity with other
        # HTTP requests, and maybe even multiple websocket sessions, but that
        # would require multithreading.
        self.log("entering websocket loop")
        while not self.close_connection:
            try:
                self.handle_ws()
            except WebSocketTimedOut:
                self.close_ws(3008, reason="timed out")
                assert self.close_connection   # i.e. we break out now
        self.log("done websocket loop")

    def read(self, nb):
        """
        Read bytes from the other end, with a timeout.
        """
        if session_timeout is not None:
            (ready, _, _) = select.select([self.rfile], [], [], session_timeout)
            if self.rfile not in ready:
                # This will likely abandon the read loop.
                raise WebSocketTimedOut
        data = self.rfile.read(nb)
        return data

    def handle_ws(self):
        """
        Process a WebSocket request from the client,
        and dispatch it to the appropriate handler.
        """
        (h1, h2) = struct.unpack("!BB", self.read(2))
        fin = h1 & 0x80
        opcode = h1 & 0x7f
        plen = h2 & 0x7f
        if plen == 0x7e:
            plen = struct.unpack("!H", self.read(2))[0]
        elif plen == 0x7f:
            plen = struct.unpack("!Q", self.read(8))[0]
        # print("WS: op=0x%02x len=%u" % (opcode, plen))
        if h2 & 0x80:
            # masking is mandatory, so we expect this
            mkey = self.read(4)
        else:
            self.warn("unexpected: WS message is not masked")
        payload = self.read(plen)
        if h2 & 0x80:
            mask = (mkey * ((plen + 4) // 4))[:plen]
            payload = bytearray(a ^ b for a, b in zip(payload, mask))
        if opcode == 0x00:
            self.ws_payload += payload
        elif opcode == 0x01:
            (self.ws_payload, self.ws_is_text) = (payload, True)
        elif opcode == 0x02:
            (self.ws_payload, self.ws_is_text) = (payload, False)
        elif opcode == 0x08:
            code = None
            if plen == 2:
                code = struct.unpack("!H", payload)[0]
            self.close_ws(code, reason="other end sent 0x08")
            return
        elif opcode == 0x09:
            send_ws_frame(0x0a, payload)
            return
        elif opcode == 0x0a:
            return
        if fin:
            if self.ws_is_text:
                self.handle_ws_text(self.ws_payload.decode("utf-8"))
            else:
                self.handle_ws_binary(self.ws_payload)

    def handle_ws_text(self, s):
        """
        Handle text request from the client.
        Assumes that text beginning '{' is JSON, and dispatches to
        JSON handler.
        """
        #self.log("WS text: \"%s\"" % s)
        if s.startswith("{"):     # TBD improve
            jreq = json.loads(s)
            self.handle_ws_json(jreq)
        else:
            self.warn("remote sent non-JSON text message: \"%s\"" % s)

    def handle_ws_json(self, jreq):
        """
        Handle a JSON request from the client. Subclass should implement.
        """
        pass

    def send_ws_frame(self, opcode, payload):
        # print("WS: send frame, opcode=0x%02x" % opcode)
        plen = len(payload)
        if plen <= 125:
            lenp = struct.pack("!B", plen)
        elif plen <= 0xffff:
            lenp = struct.pack("!BH", 0x7e, plen)
        else:
            lenp = struct.pack("!BQ", 0x7f, plen)
        self.request.send(struct.pack("!B", 0x80 | opcode) + lenp + payload)

    def send_ws_text(self, s):
        if self.log_level >= 2:
            self.log("WS: send '%s'" % s)
        self.send_ws_frame(0x01, s.encode("utf-8"))

    def send_ws_json(self, j):
        self.send_ws_text(json.dumps(j))

    def send_ws_binary(self, s):
        self.send_ws_frame(0x02, s)

    def close_ws(self, code=1000, reason=None):
        self.log("WS: closing, code=%s, reason=%s" % (code, reason))
        self.on_ws_close()
        self.send_ws_frame(0x08, struct.pack("!H", code) if (code is not None) else b"")
        self.close_connection = True

    def on_ws_close(self):
        pass

    def log(self, s):
        """
        Print a log message, with the time in milliseconds since the
        last printed message.
        """
        t_now = time.time()
        if self.t_last_log is not None:
            t = (t_now - self.t_last_log) * 1e3
        else:
            t = 0.0
        print("LOG: %6.2f %s" % (t, s), file=sys.stderr)
        self.t_last_log = t_now

    def warn(self, s):
        self.log("*** " + s)


# experiment - not got this working yet
def ssl_context():
    cx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    cx.load_cert_chain("cert.pem", "key.pem")
    cx.set_ciphers("@SECLEVEL=1:ALL")
    return cx


def serve_forever(opts, handler):
    try:
        httpd = HTTPServer((opts.host, opts.port), handler)
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            print("address/port already in use", file=sys.stderr)
        else:
            raise
        sys.exit(1)
    if opts.ssl:
        cx = ssl_context()
        httpd.socket = cx.wrap_socket(httpd.socket, server_side=True)

    if True or opts.verbose:
        print("SV: listening: %s" % str(httpd.server_address))
    httpd.serve_forever()


def add_arguments(parser, default_port=None):
    parser.add_argument("--host", type=str, default="0.0.0.0", help="hostname to listen on")
    parser.add_argument("--port", type=int, default=default_port, help="port to listen on")
    parser.add_argument("--ssl", action="store_true")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="WebSocket server test")
    add_arguments(parser, default_port=1300)
    opts = parser.parse_args()
    serve_forever(opts, WebSocketRequestHandler)
