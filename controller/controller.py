import datetime
import os
import socket
import struct
import sys
import threading
import time

from controller.merkle import get_merkle_root
from controller.protocol import Block, CbDict, Op, Transaction, TxWitness, TxOut, Script
from controller.rpc import BtcRpcClient, RPC_PORT_MAINNET


SOCKET_NAME = '\0/tmp/btcminer'

CMD_NEW_JOB = 1
CMD_STOP = -1
CMD_FOUND = 100
CMD_REQUEST = 101


class Controller:
    def __init__(self, user, passw, rpc_host='127.0.0.1', rpc_port=RPC_PORT_MAINNET, wallet_addr=''):
        self.rpc = BtcRpcClient(user, passw, rpc_host, rpc_port)
        self.sk = None

        self.cur_tmpl = None
        self.cur_prev_hash = ''
        self.cur_bits = 0
        self.extra_nonce = b''

        self.lock = threading.Lock()
        self.stop = 0
        self.block = None
        self.block_hdr = self.cb_tx = self.cur_job = b''

        self.wallet_addr = wallet_addr
        self.addr_info = {}
        self.pk_script = b''

    def renew_extra_nonce(self):
        self.extra_nonce = os.urandom(4)

    def send_new_job(self):
        if not self.cur_tmpl:
            return

        with self.lock:
            t = self.cur_tmpl

            ver = t['version']
            prev_hash = bytes.fromhex(t['previousblockhash'])[::-1]
            bits = int(t['bits'], 16)
            cur_time = t['curtime']

            self.cb_tx = Transaction(
                coinbase=CbDict(block_heigt=t['height'], reward=t['coinbasevalue'], pk_script=self.pk_script, cmds=[Op.OP_0, self.extra_nonce, b'@baskiton']),
            )
            w = t.get('default_witness_commitment')
            if w:
                self.cb_tx.tx_witnesses=[TxWitness(b'\0'*32)]
                self.cb_tx.tx_outs.append(TxOut(0, Script(w)))

            merkle = get_merkle_root(self.cb_tx, [tx['txid'] for tx in t['transactions']])

            self.block = Block(ver, prev_hash, merkle, cur_time, bits, 0, [self.cb_tx, *(tx['data'] for tx in t['transactions'])])
            self.block_hdr = self.block.get_hdr()
            self.cur_job = struct.pack('<i80s', CMD_NEW_JOB, self.block_hdr)

            if self.sk:
                try:
                    self.sk.sendall(self.cur_job)
                except socket.error as e:
                    self.detach_miner(e)

        print('job sent')

    def detach_miner(self, e=None):
        if self.sk:
            try:
                self.sk.close()
            except:
                pass

            self.sk = None
            print(f'Miner detached{e and f"; cause: {str(e)}" or ""}', file=(e and sys.stderr or sys.stdout))

    def build_and_submit(self, nonce, t):
        if not (self.cur_tmpl and self.block_hdr and self.addr_info):
            return

        with self.lock:
            self.block.nonce = nonce
            self.block.timestamp = t
            b = self.block.serialize()
            print('sending to net:', self.block.get_hash().hex())

            try:
                r = self.rpc.submit_block(b.hex())
                if r is None:
                    print('submit success!')
                else:
                    print('submit error:', r, file=sys.stderr)

            except Exception as e:
                print('RPC Error (submit)', e, file=sys.stderr)

    def btc_polling_loop(self):
        cur_lpid = None
        t = 0

        try:
            # receive scriptPubKey
            x = self.rpc.validate_address(self.wallet_addr)
            if not x['isvalid']:
                print(f'Invalid WALLET_ADDR: {x["error"]}', file=sys.stderr)
            else:
                self.addr_info = x
                self.pk_script = x['scriptPubKey']

        except Exception as e:
            print(e, file=sys.stderr)
            return

        while not self.stop:
            try:
                tmpl = self.rpc.get_block_template(cur_lpid)
                if not tmpl:
                    continue
                prev_hash = tmpl['previousblockhash']
                bits = tmpl['bits']
                lpid = tmpl['longpollid']

                now = time.time()

                if prev_hash != self.cur_prev_hash or cur_lpid is None:
                    print(f'[{datetime.datetime.now().time().strftime("%H:%M:%S")}] Net updated: date={datetime.datetime.fromtimestamp(tmpl["curtime"]).isoformat()} height={tmpl["height"]} bits={bits} txs={len(tmpl["transactions"])}')
                    self.cur_tmpl = tmpl
                    self.cur_prev_hash = prev_hash
                    self.cur_bits = bits
                    self.renew_extra_nonce()
                    t = now
                    self.send_new_job()

                elif now - t > 120 and tmpl["transactions"] != self.cur_tmpl["transactions"]:
                    print(f'[{datetime.datetime.now().time().strftime("%H:%M:%S")}] New transactions: date={datetime.datetime.fromtimestamp(tmpl["curtime"]).isoformat()} height={tmpl["height"]} bits={bits} txs={len(tmpl["transactions"])}')
                    self.cur_tmpl = tmpl
                    t = now
                    self.send_new_job()

                cur_lpid = lpid

            except Exception as e:
                print('RPC Error:', e, file=sys.stderr)
                cur_lpid = None
                time.sleep(5)

    def miner_handler(self):
        er = ''
        while not self.stop and self.sk:
            try:
                cmd = self.sk.recv(4)
                if not cmd:
                    er = 'connection lost'
                    break

                cmd, = struct.unpack('=i', cmd)
                if cmd == CMD_FOUND:
                    fmt = struct.Struct('=II')
                    x = self.sk.recv(fmt.size, socket.MSG_WAITALL)
                    self.build_and_submit(*fmt.unpack(x))

                elif cmd == CMD_REQUEST:
                    with self.lock:
                        self.renew_extra_nonce()
                    self.send_new_job()

            except socket.error as e:
                er = e
                break

        self.detach_miner(er)

    def accept_loop(self, s):
        while not self.stop:
            try:
                cli, _ = s.accept()
                with self.lock:
                    if self.sk:
                        try:
                            cli.close()
                        except:
                            pass
                        continue

                    print('client accepted')
                    self.sk = cli
                    if self.cur_tmpl:
                        print(f'send existed job')
                        print(self.cur_job[4:].hex())
                        try:
                            cli.sendall(self.cur_job)
                        except socket.error:
                            pass

                threading.Thread(target=self.miner_handler, daemon=True).start()

            except socket.error as e:
                print(e, file=sys.stderr)
                if self.stop:
                    break

    def start(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(SOCKET_NAME)
            s.listen(1)
            print('listen...')

            polling_thr = threading.Thread(target=self.btc_polling_loop, daemon=True)
            polling_thr.start()

            self.accept_loop(s)

        except KeyboardInterrupt:
            self.stop = 1
            with self.lock:
                if self.sk:
                    try:
                        self.sk.sendall(struct.pack('=i', CMD_STOP))
                    except:
                        pass
                    try:
                        self.sk.close()
                    except:
                        pass

        finally:
            s.close()
