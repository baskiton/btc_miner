from controller.controller import Controller
from controller.rpc import RPC_PORT_MAINNET, RPC_PORT_TESTNET4, RPC_PORT_REGTEST, RPC_PORT_SIGNET

RPC_USER = '<username>'
RPC_PASS = '<pass>'

creds = {
    'main': (RPC_PORT_MAINNET, '<wallet address>'),
    'regtest': (RPC_PORT_REGTEST, '<wallet address>'),
    'testnet4': (RPC_PORT_TESTNET4, '<wallet address>'),
    # 'signet': (RPC_PORT_SIGNET, '<wallet address>'),
}


if __name__ == '__main__':
    NET = 'main'

    kw = dict(zip(('rpc_port', 'wallet_addr'), creds[NET]))
    c = Controller(RPC_USER, RPC_PASS, **kw)
    c.start()
