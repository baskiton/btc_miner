from .common import sha256d
from .protocol import CbDict, Op, Script, Transaction, TxOut, TxWitness


def _merkle_root(lvl):
    while len(lvl) > 1:
        nxt = []
        for i in range(0, len(lvl), 2):
            l = lvl[i]
            i += 1
            r = lvl[i] if i < len(lvl) else l
            nxt.append(sha256d(l + r))
        lvl = nxt
    return lvl[0]


def get_merkle_root(cb_tx: Transaction | str | bytes, txids: list[str] = ()):
    if isinstance(cb_tx, Transaction):
        cb_tx = bytes.fromhex(cb_tx.txid())[::-1]
    elif isinstance(cb_tx, str):
        cb_tx = bytes.fromhex(cb_tx)[::-1]

    lvl = [cb_tx] + [bytes.fromhex(txid)[::-1] for txid in txids]

    while len(lvl) > 1:
        nxt = []
        for i in range(0, len(lvl), 2):
            l = lvl[i]
            i += 1
            r = lvl[i] if i < len(lvl) else l
            nxt.append(sha256d(l + r))
        lvl = nxt

    return lvl[0]


if __name__ == '__main__':
    cb = Transaction(1, coinbase=CbDict(block_heigt=150412, reward=5000002875, pk_script='001485e9d16efcd61814f84fd2c8e996768ba43fc31c', cmds=[Op.OP_0, '7a42946a', 'f5ca816a0000000000000000']),
                     # tx_outs=[TxOut(0, Script.from_commands(Op.OP_RETURN, 'aa21a9edb6462b3bf9f865d98c2ddd855d6b9cb8429e8571c47809f38edc7baa5f94efa0'))],
                     tx_outs=[TxOut(0, Script(bytes.fromhex('6a24aa21a9edb6462b3bf9f865d98c2ddd855d6b9cb8429e8571c47809f38edc7baa5f94efa0')))],
                     tx_witnesses=[TxWitness(b'\0' * 32)])

    print('bcc64fec4c3443c6b52a64e2a573d23e54a2a5ec1a77e8190b67571bba7215a5')
    print(cb.txid())
    print(cb.wtxid())
    print()

    txids = [
        'bcc64fec4c3443c6b52a64e2a573d23e54a2a5ec1a77e8190b67571bba7215a5',
        'a3973da3c76e5776069c19b29d3c4c2554301def2996c717269bc2625c5038ce',
        '55d8702abb9ebbb3bb4633c646c0adb02f2e00e55930f426776821dfeb781eb1',
    ]
    root_expect = bytes.fromhex('0ad221637dbf4ff02bf4701f5623fffa330ea13803a3a50a97fa65d633eda1b9')#[::-1]

    #       version  witn txs outpoint                                                                 script                                            seq      txo reward           script
    '       02000000 0001 01  0000000000000000000000000000000000000000000000000000000000000000ffffffff 08 52000568656c6c6f                               ffffffff 01  00f2052a01000000 16 0014450b1f21d8400ee525d2a30f39c8a6392047f60c                                                                                                  0120000000000000000000000000000000000000000000000000000000000000000000000000'
    tx_h = '01000000 0001 01  0000000000000000000000000000000000000000000000000000000000000000ffffffff 17 038c4b0200047a42946a0cf5ca816a0000000000000000 ffffffff 02  3bfd052a01000000 16 001485e9d16efcd61814f84fd2c8e996768ba43fc31c 0000000000000000 26 6a24aa21a9edb6462b3bf9f865d98c2ddd855d6b9cb8429e8571c47809f38edc7baa5f94efa0 0120000000000000000000000000000000000000000000000000000000000000000000000000'
    print(tx_h)
    print(cb.serialize(wt=1).hex())
    print()

    print('exp:', root_expect.hex())
    root = get_merkle_root(cb, txids[1:])[::-1]
    print('res:', root.hex())
    print(root_expect == root)

    print(_merkle_root([bytes.fromhex(i)[::-1] for i in txids])[::-1].hex())
