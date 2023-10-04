#!/usr/bin/env python3
#
# Example 1-1 call signalling server
#
# Copyright (C) 2017 Centricular Ltd.
#
#  Author: Nirbheek Chauhan <nirbheek@centricular.com>
#

import os
import sys
import ssl
import logging
import asyncio
import websockets
import argparse
import http
import concurrent
import json


class WebRTCSimpleServer(object):

    def __init__(self, loop, options):
        ############### Global data ###############

        # Format: {uid: (Peer WebSocketServerProtocol,
        #                remote_address,
        #                <'session'|room_id|None>)}
        self.peers = dict()
        # Format: {caller_uid: callee_uid,
        #          callee_uid: caller_uid}
        # Bidirectional mapping between the two peers
        self.sessions = dict()
        # Format: {room_id: {peer1_id, peer2_id, peer3_id, ...}}
        # Room dict with a set of peers in each room
        self.rooms = dict()
        self.ref = dict()

        # Event loop
        self.loop = loop
        # Websocket Server Instance
        self.server = None

        # Options
        self.addr = options.addr
        self.port = options.port
        self.keepalive_timeout = options.keepalive_timeout
        self.cert_restart = options.cert_restart
        self.cert_path = options.cert_path
        self.disable_ssl = options.disable_ssl
        self.health_path = options.health

        # Certificate mtime, used to detect when to restart the server
        self.cert_mtime = -1

    ############### Helper functions ###############

    async def health_check(self, path, request_headers):
        if path == self.health_path:
            return http.HTTPStatus.OK, [], b"OK\n"
        return None

    async def recv_msg_ping(self, ws, raddr):
        '''
        Wait for a message forever, and send a regular ping to prevent bad routers
        from closing the connection.
        '''
        msg = None
        while msg is None:
            try:
                msg = await asyncio.wait_for(ws.recv(), self.keepalive_timeout)
            except (asyncio.TimeoutError, concurrent.futures._base.TimeoutError):
                print('Sending keepalive ping to {!r} in recv'.format(raddr))
                await ws.ping()
        return msg

    async def remove_peer(self, uid):
        if uid in self.peers:
            ws = self.peers[uid]
            if uid in self.ref:
                wso = self.peers[self.ref[uid]]
                await wso.send("left"+uid)
                del self.ref[uid]


            del self.peers[uid]
            await ws.close()
            print("Disconnected from peer {!r}".format(uid))

    ############### Handler functions ###############

    
    async def connection_handler(self, ws, uid):
        raddr = ws.remote_address
        peer_status = None
        self.peers[uid] = ws        
        print("Registered peer {!r} at {!r}".format(uid, raddr))
        while True:
            # Receive command, wait forever if necessary
            msg = await self.recv_msg_ping(ws, raddr)
            if(msg.startswith('SESSION')):
                _, callee_id = msg.split(maxsplit=1)
                if callee_id in self.peers.keys():
                    self.ref[uid] = callee_id
                    wso = self.peers[callee_id]
                    await wso.send("KABOOM"+uid)            

                else:
                    await ws.send('ERROR peer {!r} not found'.format(callee_id))
                    continue          
            else:
                y = json.loads(msg)
                if "tosend" in y:
                    tosendpeer = (y["tosend"])
                    wso = self.peers[tosendpeer]
                    await wso.send(msg)
                    print("message sent from {!r} to {!r}".format(uid, tosendpeer))
                else:
                    print('Ignoring unknown message {!r} from {!r}'.format(msg, uid))
          
    async def hello_peer(self, ws):
        '''
        Exchange hello, register peer
        '''
        raddr = ws.remote_address
        hello = await ws.recv()
        hello, uid = hello.split(maxsplit=1)
        if hello != 'HELLO':
            await ws.close(code=1002, reason='invalid protocol')
            raise Exception("Invalid hello from {!r}".format(raddr))
        if not uid or uid in self.peers or uid.split() != [uid]: # no whitespace
            await ws.close(code=1002, reason='invalid peer uid')
            raise Exception("Invalid uid {!r} from {!r}".format(uid, raddr))
        # Send back a HELLO
        await ws.send('HELLO')
        return uid

    def get_ssl_certs(self):
        if 'letsencrypt' in self.cert_path:
            chain_pem = os.path.join(self.cert_path, 'fullchain.pem')
            key_pem = os.path.join(self.cert_path, 'privkey.pem')
        else:
            chain_pem = os.path.join(self.cert_path, 'cert.pem')
            key_pem = os.path.join(self.cert_path, 'key.pem')
        return chain_pem, key_pem

    def get_ssl_ctx(self):
        if self.disable_ssl:
            return None
        # Create an SSL context to be used by the websocket server
        print('Using TLS with keys in {!r}'.format(self.cert_path))
        chain_pem, key_pem = self.get_ssl_certs()
        sslctx = ssl.create_default_context()
        try:
            sslctx.load_cert_chain(chain_pem, keyfile=key_pem)
        except FileNotFoundError:
            print("Certificates not found, did you run generate_cert.sh?")
            sys.exit(1)
        # FIXME
        sslctx.check_hostname = False
        sslctx.verify_mode = ssl.CERT_NONE
        return sslctx

    def run(self):
        async def handler(ws, path):
            '''
            All incoming messages are handled here. @path is unused.
            '''
            raddr = ws.remote_address
            print("Connected to {!r}".format(raddr))
            peer_id = await self.hello_peer(ws)
            try:
                await self.connection_handler(ws, peer_id)
            except websockets.ConnectionClosed:
                print("Connection to peer {!r} closed, exiting handler".format(raddr))
            finally:
                await self.remove_peer(peer_id)

        sslctx = self.get_ssl_ctx()

        print("Listening on https://{}:{}".format(self.addr, self.port))
        # Websocket server
        wsd = websockets.serve(handler, self.addr, self.port, ssl=sslctx, process_request=self.health_check if self.health_path else None,
                               # Maximum number of messages that websockets will pop
                               # off the asyncio and OS buffers per connection. See:
                               # https://websockets.readthedocs.io/en/stable/api.html#websockets.protocol.WebSocketCommonProtocol
                               max_queue=16)

        # Setup logging
        logger = logging.getLogger('websockets')
        logger.setLevel(logging.INFO)
        logger.addHandler(logging.StreamHandler())

        # Run the server
        self.server = self.loop.run_until_complete(wsd)
        # Stop the server if certificate changes
        self.loop.run_until_complete(self.check_server_needs_restart())

    async def stop(self):
        print('Stopping server... ', end='')
        self.server.close()
        await self.server.wait_closed()
        self.loop.stop()
        print('Stopped.')

    def check_cert_changed(self):
        chain_pem, key_pem = self.get_ssl_certs()
        mtime = max(os.stat(key_pem).st_mtime, os.stat(chain_pem).st_mtime)
        if self.cert_mtime < 0:
            self.cert_mtime = mtime
            return False
        if mtime > self.cert_mtime:
            self.cert_mtime = mtime
            return True
        return False

    async def check_server_needs_restart(self):
        "When the certificate changes, we need to restart the server"
        if not self.cert_restart:
            return
        while True:
            await asyncio.sleep(10)
            if self.check_cert_changed():
                print('Certificate changed, stopping server...')
                await self.stop()
                return


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    # See: host, port in https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.create_server
    parser.add_argument('--addr', default='192.168.100.202', help='Address to listen on (default: all interfaces, both ipv4 and ipv6)')
    parser.add_argument('--port', default=6504, type=int, help='Port to listen on')
    parser.add_argument('--keepalive-timeout', dest='keepalive_timeout', default=30, type=int, help='Timeout for keepalive (in seconds)')
    parser.add_argument('--cert-path', default=os.path.dirname(__file__))
    parser.add_argument('--disable-ssl', default='Disable ssl', help='Disable ssl', action='store_true')
    parser.add_argument('--health', default='/health', help='Health check route')
    parser.add_argument('--restart-on-cert-change', default=False, dest='cert_restart', action='store_true', help='Automatically restart if the SSL certificate changes')

    options = parser.parse_args(sys.argv[1:])

    loop = asyncio.get_event_loop()

    r = WebRTCSimpleServer(loop, options)

    print('Starting server...')
    while True:
        r.run()
        loop.run_forever()
        print('Restarting server...')
    print("Goodbye!")

if __name__ == "__main__":
    main()
