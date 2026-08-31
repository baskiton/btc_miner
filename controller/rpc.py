import base64
import json
import urllib
import urllib.error
import urllib.request


RPC_PORT_MAINNET = 8332
RPC_PORT_REGTEST = 18332
RPC_PORT_SIGNET = 38332
RPC_PORT_TESTNET4 = 48332


class BtcRpcClient:
    def __init__(self, user, password, host='127.0.0.1', port=RPC_PORT_MAINNET):
        self.url = f'http://{host}:{port}/'
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic {base64.b64encode(f"{user}:{password}".encode('utf8')).decode('utf8')}',
        }

    def _call(self, method, params=None, timeout=10):
        if params is None:
            params = []

        payload = dict(
            jsonrpc='1.0',
            id='baskiton',
            method=method,
            params=params,
        )
        req = urllib.request.Request(
            url=self.url,
            data=json.dumps(payload).encode('utf8'),
            headers=self.headers,
            method='POST',
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                res = json.loads(resp.read().decode('utf8'))
                e = res.get('error')
                if e:
                    raise Exception(f'RPC Error: {e}')
                return res.get('result')

        except urllib.error.HTTPError as e:
            msg = e.read().decode('utf8')
            try:
                j = json.loads(msg)
                raise Exception(f'HTTP RPC Error ({e.code}): {j.get("error")}')
            except json.JSONDecodeError:
                raise Exception(f'HTTP Error ({e.code}): {msg}')

        except urllib.error.URLError as e:
            raise Exception(f'Failed to connect: {e.reason}')

    def get_block_template(self, longpollid=None):
        p = dict(
                rules=['segwit'],
                capabilities=['coinbasetxn'],
        )
        if longpollid:
            to = 600
            p['longpollid'] = longpollid
        else:
            to = 10

        return self._call('getblocktemplate', [p], timeout=to)

    def submit_block(self, block_hex):
        return self._call('submitblock', [block_hex])

    def submit_header(self, hdr_hex):
        return self._call('submitheader', [hdr_hex])

    def get_block_header(self, blockhash, verbose=True):
        return self._call('getblockheader', [blockhash, bool(verbose)])

    def get_block(self, blockhash, verbose=True):
        return self._call('getblock', [blockhash, bool(verbose)])

    def get_blockhash(self, height):
        return self._call('getblockhash', [height])

    def get_blockchain_info(self):
        return self._call('getblockchaininfo')

    def validate_address(self, addr):
        return self._call('validateaddress', [addr])

    def help(self, cmd=None):
        return self._call('help', cmd and [cmd])
