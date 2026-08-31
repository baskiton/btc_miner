import enum
import hashlib
import struct

from typing import Iterable, TypedDict, Union


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def varint(v):
    if v < 0xfd:
        r = struct.pack('<B', v)
    elif v <= 0xffff:
        r = b'\xfd' + struct.pack('<H', v)
    elif v <= 0xffffffff:
        r = b'\xfe' + struct.pack('<I', v)
    else:
        r = b'\xff' + struct.pack('<Q', v)
    return r


def script_num(v):
    if 1 <= v <= 16:
        return Op((0x50 + v).to_bytes(1))
    x = struct.pack('<Q', v).rstrip(b'\0')
    if not x or (x[-1] & 0x80):
        x += b'\0'
    return x


def base58_decode(v):
    digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = 0
    for ch in v:
        num = num * 58 + digits.index(ch)
    return num.to_bytes(25, byteorder='big')


class _BtcProto:

    def serialize(self, **kw):
        return b''.join(self._serialize(**kw))

    def _serialize(self, **kw) -> tuple[bytes]:
        raise NotImplementedError


class Op(enum.Enum):
    """
    see https://en.bitcoin.it/wiki/Script
    """

    # constats
    OP_0 = OP_FALSE = b'\x00'
    OP_PUSHDATA1 = b'\x4c'
    OP_PUSHDATA2 = b'\x4d'
    OP_PUSHDATA4 = b'\x4e'
    OP_1NEGATE = b'\x4f'
    OP_1 = OP_TRUE = b'\x51'
    OP_2 = b'\x52'
    OP_3 = b'\x53'
    OP_4 = b'\x54'
    OP_5 = b'\x55'
    OP_6 = b'\x56'
    OP_7 = b'\x57'
    OP_8 = b'\x58'
    OP_9 = b'\x59'
    OP_10 = b'\x5a'
    OP_11 = b'\x5b'
    OP_12 = b'\x5c'
    OP_13 = b'\x5d'
    OP_14 = b'\x5e'
    OP_15 = b'\x5f'
    OP_16 = b'\x60'

    # flow control
    OP_NOP = b'\x61'
    OP_IF = b'\x63'
    OP_NOTIF = b'\x64'
    OP_ELSE = b'\x67'
    OP_ENDIF = b'\x68'
    OP_VERIFY = b'\x69'
    OP_RETURN = b'\x6a'

    # stack
    OP_TOALTSTACK = b'\x6b'
    OP_FROMALTSTACK = b'\x6c'
    OP_IFDUP = b'\x73'
    OP_DEPTH = b'\x74'
    OP_DROP = b'\x75'
    OP_DUP = b'\x76'
    OP_NIP = b'\x77'
    OP_OVER = b'\x78'
    OP_PICK = b'\x79'
    OP_ROLL = b'\x7a'
    OP_ROT = b'\x7b'
    OP_SWAP = b'\x7c'
    OP_TUCK = b'\x7d'
    OP_2DROP = b'\x6d'
    OP_2DUP = b'\x6e'
    OP_3DUP = b'\x6f'
    OP_2OVER = b'\x70'
    OP_2ROT = b'\x71'
    OP_2SWAP = b'\x72'

    # splice
    # OP_CAT = b'\x7e'    # disabled
    # OP_SUBSTR = b'\x7f' # disabled
    # OP_LEFT = b'\x80'   # disabled
    # OP_RIGHT = b'\x81'  # disabled
    OP_SIZE = b'\x82'

    # bitwise logic
    # OP_INVERT = b'\x83' # disabled
    # OP_AND = b'\x84'    # disabled
    # OP_OR = b'\x85'     # disabled
    # OP_XOR = b'\x86'    # disabled
    OP_EQUAL = b'\x87'
    OP_EQUALVERIFY = b'\x88'

    #arithmetic
    OP_1ADD = b'\x8b'
    OP_1SUB = b'\x8c'
    # OP_2MUL = b'\x8d'   # disabled
    # OP_2DIV = b'\x8e'   # disabled
    OP_NEGATE = b'\x8f'
    OP_ABS = b'\x90'
    OP_NOT = b'\x91'
    OP_0NOTEQUAL = b'\x92'
    OP_ADD = b'\x93'
    OP_SUB = b'\x94'
    # OP_MUL = b'\x95'    # disabled
    # OP_DIV = b'\x96'    # disabled
    # OP_MOD = b'\x97'    # disabled
    # OP_LSHIFT = b'\x98' # disabled
    # OP_RSHIFT = b'\x99' # disabled
    OP_BOOLAND = b'\x9a'
    OP_BOOLOR = b'\x9b'
    OP_NUMEQUAL = b'\x9c'
    OP_NUMEQUALVERIFY = b'\x9d'
    OP_NUMNOTEQUAL = b'\x9e'
    OP_LESSTHAN = b'\x9f'
    OP_GREATERTHAN = b'\xa0'
    OP_LESSTHANOREQUAL = b'\xa1'
    OP_GREATERTHANOREQUAL = b'\xa2'
    OP_MIN = b'\xa3'
    OP_MAX = b'\xa4'
    OP_WITHIN = b'\xa5'

    # crypto
    OP_RIPEMD160 = b'\xa6'
    OP_SHA1 = b'\xa7'
    OP_SHA256 = b'\xa8'
    OP_HASH160 = b'\xa9'
    OP_HASH256 = b'\xaa'
    OP_CODESEPARATOR = b'\xab'
    OP_CHECKSIG = b'\xac'
    OP_CHECKSIGVERIFY = b'\xad'
    OP_CHECKMULTISIG = b'\xae'
    OP_CHECKMULTISIGVERIFY = b'\xaf'
    OP_CHECKSIGADD = b'\xba'

    # locktime
    OP_CHECKLOCKTIMEVERIFY = b'\xb1'
    OP_CHECKSEQUENCEVERIFY = b'\xb2'

    # resetved
    OP_RESERVED = b'\x50'
    OP_VER = b'\x62'
    OP_VERIF = b'\x65'
    OP_VERNOTIF = b'\x66'
    OP_RESERVED1 = b'\x89'
    OP_RESERVED2 = b'\x8a'
    OP_NOP1 = b'\xb0'
    OP_NOP4 = b'\xb3'
    OP_NOP5 = b'\xb4'
    OP_NOP6 = b'\xb5'
    OP_NOP7 = b'\xb6'
    OP_NOP8 = b'\xb7'
    OP_NOP9 = b'\xb8'
    OP_NOP10 = b'\xb9'


class Script(_BtcProto):
    # disables_ops = (
    #     Opcode.OP_CAT, Opcode.OP_SUBSTR, Opcode.OP_LEFT, Opcode.OP_RIGHT,
    #     Opcode.OP_2MUL, Opcode.OP_2DIV, Opcode.OP_MUL, Opcode.OP_DIV,
    #     Opcode.OP_MOD, Opcode.OP_LSHIFT, Opcode.OP_RSHIFT,
    # )

    def __init__(self, script):
        super().__init__()
        self.script = bytes.fromhex(script) if isinstance(script, str) else script

    @classmethod
    def coinbase(cls, block_heigt, cmds=()):
        return cls.from_commands(script_num(block_heigt), *cmds)

    @classmethod
    def from_commands(cls, *cmds: Union[Op, bytes, str]):
        compiled = []
        for cmd in cmds:
            if isinstance(cmd, Op):
                compiled.append(cmd.value)
            elif isinstance(cmd, bytes):
                compiled.append(cls._build_pushdata(cmd))
            elif isinstance(cmd, str):
                compiled.append(cls._build_pushdata(bytes.fromhex(cmd)))
            else:
                raise TypeError(f'cmd must be bytes, got {type(cmd)}')
        return cls(b''.join(compiled))

    @staticmethod
    def _build_pushdata(data: bytes):
        d_len = len(data)
        if d_len < 0x4c:
            a = b''
            fmt = '<B'
        elif d_len <= 0xff:
            a = b'\x4c'
            fmt = '<B'
        elif d_len <= 0xffff:
            a = b'\x4d'
            fmt = '<H'
        else:
            a = b'\x4e'
            fmt = '<I'
        return a + struct.pack(fmt, d_len) + data

    def _serialize(self):
        return (
            varint(len(self.script)),
            self.script,
        )


class OutPoint(_BtcProto):
    def __init__(self, prev_txid: str | bytes = None, outnode_index: int = None):
        super().__init__()
        if prev_txid is None and outnode_index is None:
            # is coinbase
            self.prev_txid = b'\0' * 32
            self.outnode_index = 0xffffffff
        elif not (prev_txid is None or outnode_index is None):
            self.prev_txid = prev_txid if isinstance(prev_txid, bytes) else bytes.fromhex(prev_txid)[::-1]
            self.outnode_index = outnode_index
        else:
            raise ValueError('prev_txid and outnode_index must be both, or noone for coinbase')

    def _serialize(self):
        return (
            self.prev_txid,
            struct.pack('<I', self.outnode_index)
        )


class TxIn(_BtcProto):
    def __init__(self, prev_outpoint: OutPoint, script_sig: Script, seq=0xffffffff):
        super().__init__()
        self.prev_outpoint = prev_outpoint
        self.script_sig = script_sig
        self.seq = seq

    def _serialize(self):
        return (
            self.prev_outpoint.serialize(),
            self.script_sig.serialize(),
            struct.pack('<I', self.seq),
        )


class TxOut(_BtcProto):
    def __init__(self, val, pk_script: Script):
        super().__init__()
        self.val = val
        self.pk_script = pk_script

    def _serialize(self):
        return (
            struct.pack('<q', self.val),
            self.pk_script.serialize(),
        )


class TxWitness(_BtcProto):
    def __init__(self, *witnesses: bytes):
        super().__init__()
        self.witnesses = witnesses

    def _serialize(self):
        return (
            varint(len(self.witnesses)),
            *(varint(len(w)) + w for w in self.witnesses),
        )


class CbDict(TypedDict):
    block_heigt: int
    reward: int | float
    pk_script: str | bytes
    cmds: Iterable[Union[Op, bytes, str]]


class Transaction(_BtcProto):

    @classmethod
    def frombytes(cls, b):
        off = 0
        v = struct.unpack_from('<I', b, off)
        off += 4
        raise NotImplementedError

    def __init__(self,
                 version=2,
                 tx_ins: Iterable[TxIn] = None,
                 tx_outs: Iterable[TxOut] = None,
                 tx_witnesses: Iterable[TxWitness] = None,
                 lock_time=0,
                 coinbase: CbDict = None,
                 ):
        super().__init__()
        # if version < 2:
        #     raise ValueError('version must be at least 2')

        self.version = version
        self.tx_ins = list(tx_ins) if tx_ins else []
        self.tx_outs = list(tx_outs) if tx_outs else []
        self.tx_witnesses = list(tx_witnesses) if tx_witnesses else []
        self.lock_time = lock_time
        self.coinbase = coinbase

        if coinbase:
            try:
                block_heigt = coinbase['block_heigt']
                reward = coinbase['reward']
                pk_script = coinbase['pk_script']
                cmds = coinbase['cmds']
            except KeyError as e:
                raise ValueError(f'for coinbase "{e}" must be specified')
            self.tx_ins = TxIn(OutPoint(), Script.coinbase(block_heigt, cmds)),
            self.tx_outs = [(TxOut(reward, Script(pk_script)))] + self.tx_outs

    def _serialize(self, wt=True):
        return (
            struct.pack('<I', self.version),
            b'\0\1' if wt and self.tx_witnesses else b'',   # flag - segwit marker
            varint(len(self.tx_ins)),
            b''.join(t.serialize() for t in self.tx_ins),
            varint(len(self.tx_outs)),
            b''.join(t.serialize() for t in self.tx_outs),
            b''.join(t.serialize() for t in (wt and self.tx_witnesses or ())),
            struct.pack('<I', self.lock_time),
        )

    def txid(self):
        return sha256d(self.serialize(wt=0))[::-1].hex()

    def wtxid(self):
        return sha256d(self.serialize(wt=1))[::-1].hex()


class Block(_BtcProto):
    def __init__(self, ver, prev_block, merkle, timestamp, bits, nonce, txns: list[Transaction|str|bytes] = None):
        super().__init__()
        self.ver = ver
        self.prev_block = prev_block
        self.merkle = merkle
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.txns = txns or []

    def get_hdr(self):
        return self.serialize(with_tx=False)

    def get_hash(self):
        return sha256d(self.get_hdr())[::-1]

    def _serialize(self, with_tx=True):
        txs = []
        if with_tx:
            txs.append(varint(len(self.txns)))
            for tx in self.txns:
                if isinstance(tx, Transaction):
                    tx = tx.serialize()
                elif isinstance(tx, str):
                    tx = bytes.fromhex(tx)
                txs.append(tx)
        return (
            struct.pack('<I32s32sIII', self.ver, self.prev_block, self.merkle, self.timestamp, self.bits, self.nonce),
            *txs,
        )


if __name__ == '__main__':
    '00000020028105aa800da39f47d3df59e07c198ea27f7efebda076367c3e45813420ec1c9dbcb3d2bfa6f3ad767e1e791109532ed3f97c6163e909232e2faebe5f36cf0d8f64946affff7f20 03001000'
    b = Block(633389056, bytes.fromhex('00000000007bb043f3304b9ffcb23d0a1b5d71a73c4e78b98a70d1b4ba9879e8')[::-1],
              bytes.fromhex('0ad221637dbf4ff02bf4701f5623fffa330ea13803a3a50a97fa65d633eda1b9')[::-1],
              1788107957, int('1d00ffff', 16), 420938064, [
            'bcc64fec4c3443c6b52a64e2a573d23e54a2a5ec1a77e8190b67571bba7215a5',
            'a3973da3c76e5776069c19b29d3c4c2554301def2996c717269bc2625c5038ce',
            '55d8702abb9ebbb3bb4633c646c0adb02f2e00e55930f426776821dfeb781eb1',
              ])
    print(b.get_hdr().hex())
    print(b.get_hash().hex())
