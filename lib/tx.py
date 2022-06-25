# Copyright (c) 2016-2017, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# and warranty status of this software.

'''Transaction-related classes and functions.'''

import hashlib
import struct
import time

import msgpack
from collections import namedtuple
from dataclasses import dataclass
from hashlib import blake2s
from typing import Sequence
from electrumx.lib.hash import sha256, double_sha256, hash_to_hex_str, hash_to_hex_str
from electrumx.lib.script import OpCodes
from electrumx.lib.util import (
    unpack_le_int32_from, unpack_le_int64_from, unpack_le_uint16_from,
    unpack_be_uint16_from,
    unpack_le_uint32_from, unpack_le_uint64_from, pack_le_int32, pack_varint,
    pack_le_uint16, pack_le_uint32, pack_le_int64, pack_varbytes,
)
from lbryschema.proto.claim_pb2 import Claim
from lbryschema.uri import parse_lbry_uri
from lbryschema.decode import smart_decode
from lib.coins import BlockProcessor
from lib.lbcmodel import *

ZERO = bytes(32)
MINUS_1 = 4294967295


class Tx(namedtuple("Tx", "version inputs outputs locktime")):
    '''Class representing a transaction.'''

    def serialize(self):
        return b''.join((
            pack_le_int32(self.version),
            pack_varint(len(self.inputs)),
            b''.join(tx_in.serialize() for tx_in in self.inputs),
            pack_varint(len(self.outputs)),
            b''.join(tx_out.serialize() for tx_out in self.outputs),
            pack_le_uint32(self.locktime)
        ))


class TxInput(namedtuple("TxInput", "prev_hash prev_idx script sequence")):
    '''Class representing a transaction input.'''
    def __str__(self):
        script = self.script.hex()
        prev_hash = hash_to_hex_str(self.prev_hash)
        return ("Input({}, {:d}, script={}, sequence={:d})"
                .format(prev_hash, self.prev_idx, script, self.sequence))

    def is_generation(self):
        '''Test if an input is generation/coinbase like'''
        return self.prev_idx == MINUS_1 and self.prev_hash == ZERO

    def serialize(self):
        return b''.join((
            self.prev_hash,
            pack_le_uint32(self.prev_idx),
            pack_varbytes(self.script),
            pack_le_uint32(self.sequence),
        ))


class TxOutput(namedtuple("TxOutput", "value pk_script")):

    def serialize(self):
        return b''.join((
            pack_le_int64(self.value),
            pack_varbytes(self.pk_script),
        ))


class Deserializer(object):
    '''Deserializes blocks into transactions.

    External entry points are read_tx(), read_tx_and_hash(),
    read_tx_and_vsize() and read_block().

    This code is performance sensitive as it is executed 100s of
    millions of times during sync.
    '''

    TX_HASH_FN = staticmethod(double_sha256)

    def __init__(self, binary, start=0):
        assert isinstance(binary, bytes)
        self.binary = binary
        self.binary_length = len(binary)
        self.cursor = start

    def read_tx(self):
        '''Return a deserialized transaction.'''
        return Tx(
            self._read_le_int32(),  # version
            self._read_inputs(),    # inputs
            self._read_outputs(),   # outputs
            self._read_le_uint32()  # locktime
        )

    def read_tx_and_hash(self):
        '''Return a (deserialized TX, tx_hash) pair.

        The hash needs to be reversed for human display; for efficiency
        we process it in the natural serialized order.
        '''
        start = self.cursor
        return self.read_tx(), self.TX_HASH_FN(self.binary[start:self.cursor])

    def read_tx_and_vsize(self):
        '''Return a (deserialized TX, vsize) pair.'''
        return self.read_tx(), self.binary_length

    def read_tx_block(self):
        '''Returns a list of (deserialized_tx, tx_hash) pairs.'''
        read = self.read_tx_and_hash
        # Some coins have excess data beyond the end of the transactions
        return [read() for _ in range(self._read_varint())]

    def _read_inputs(self):
        read_input = self._read_input
        return [read_input() for i in range(self._read_varint())]

    def _read_input(self):
        return TxInput(
            self._read_nbytes(32),   # prev_hash
            self._read_le_uint32(),  # prev_idx
            self._read_varbytes(),   # script
            self._read_le_uint32()   # sequence
        )

    def _read_outputs(self):
        read_output = self._read_output
        return [read_output() for i in range(self._read_varint())]

    def _read_output(self):
        return TxOutput(
            self._read_le_int64(),  # value
            self._read_varbytes(),  # pk_script
        )

    def _read_byte(self):
        cursor = self.cursor
        self.cursor += 1
        return self.binary[cursor]

    def _read_nbytes(self, n):
        cursor = self.cursor
        self.cursor = end = cursor + n
        assert self.binary_length >= end
        return self.binary[cursor:end]

    def _read_varbytes(self):
        return self._read_nbytes(self._read_varint())

    def _read_varint(self):
        n = self.binary[self.cursor]
        self.cursor += 1
        if n < 253:
            return n
        if n == 253:
            return self._read_le_uint16()
        if n == 254:
            return self._read_le_uint32()
        return self._read_le_uint64()

    def _read_le_int32(self):
        result, = unpack_le_int32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_int64(self):
        result, = unpack_le_int64_from(self.binary, self.cursor)
        self.cursor += 8
        return result

    def _read_le_uint16(self):
        result, = unpack_le_uint16_from(self.binary, self.cursor)
        self.cursor += 2
        return result

    def _read_be_uint16(self):
        result, = unpack_be_uint16_from(self.binary, self.cursor)
        self.cursor += 2
        return result

    def _read_le_uint32(self):
        result, = unpack_le_uint32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_uint64(self):
        result, = unpack_le_uint64_from(self.binary, self.cursor)
        self.cursor += 8
        return result


class TxSegWit(namedtuple("Tx", "version marker flag inputs outputs "
                          "witness locktime")):
    '''Class representing a SegWit transaction.'''


class DeserializerSegWit(Deserializer):

    # https://bitcoincore.org/en/segwit_wallet_dev/#transaction-serialization

    def _read_witness(self, fields):
        read_witness_field = self._read_witness_field
        return [read_witness_field() for i in range(fields)]

    def _read_witness_field(self):
        read_varbytes = self._read_varbytes
        return [read_varbytes() for i in range(self._read_varint())]

    def _read_tx_parts(self):
        '''Return a (deserialized TX, tx_hash, vsize) tuple.'''
        start = self.cursor
        marker = self.binary[self.cursor + 4]

        # print(marker)

        if marker:
            tx = super().read_tx()
            tx_hash = self.TX_HASH_FN(self.binary[start:self.cursor])
            return tx, tx_hash, self.binary_length

        # Ugh, this is nasty.
        version = self._read_le_int32()
        orig_ser = self.binary[start:self.cursor]

        marker = self._read_byte()
        flag = self._read_byte()

        start = self.cursor
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        orig_ser += self.binary[start:self.cursor]

        base_size = self.cursor - start
        witness = self._read_witness(len(inputs))

        start = self.cursor
        locktime = self._read_le_uint32()
        orig_ser += self.binary[start:self.cursor]
        vsize = (3 * base_size + self.binary_length) // 4

        return TxSegWit(version, marker, flag, inputs, outputs, witness,
                        locktime), self.TX_HASH_FN(orig_ser), vsize

    def read_tx(self):
        return self._read_tx_parts()[0]

    def read_tx_and_hash(self):
        tx, tx_hash, _vsize = self._read_tx_parts()
        return tx, tx_hash

    def read_tx_and_vsize(self):
        tx, _tx_hash, vsize = self._read_tx_parts()
        return tx, vsize


class DeserializerAuxPow(Deserializer):
    VERSION_AUXPOW = (1 << 8)

    def read_auxpow(self):
        '''Reads and returns the CAuxPow data'''

        # We first calculate the size of the CAuxPow instance and then
        # read it as bytes in the final step.
        start = self.cursor

        self.read_tx()  # AuxPow transaction
        self.cursor += 32  # Parent block hash
        merkle_size = self._read_varint()
        self.cursor += 32 * merkle_size  # Merkle branch
        self.cursor += 4  # Index
        merkle_size = self._read_varint()
        self.cursor += 32 * merkle_size  # Chain merkle branch
        self.cursor += 4  # Chain index
        self.cursor += 80  # Parent block header

        end = self.cursor
        self.cursor = start
        return self._read_nbytes(end - start)

    def read_header(self, static_header_size):
        '''Return the AuxPow block header bytes'''

        # We are going to calculate the block size then read it as bytes
        start = self.cursor

        version = self._read_le_uint32()
        if version & self.VERSION_AUXPOW:
            self.cursor = start
            self.cursor += static_header_size  # Block normal header
            self.read_auxpow()
            header_end = self.cursor
        else:
            header_end = start + static_header_size

        self.cursor = start
        return self._read_nbytes(header_end - start)


class DeserializerAuxPowSegWit(DeserializerSegWit, DeserializerAuxPow):
    pass


class DeserializerEquihash(Deserializer):
    def read_header(self, static_header_size):
        '''Return the block header bytes'''
        start = self.cursor
        # We are going to calculate the block size then read it as bytes
        self.cursor += static_header_size
        solution_size = self._read_varint()
        self.cursor += solution_size
        header_end = self.cursor
        self.cursor = start
        return self._read_nbytes(header_end)


class DeserializerEquihashSegWit(DeserializerSegWit, DeserializerEquihash):
    pass


class TxJoinSplit(namedtuple("Tx", "version inputs outputs locktime")):
    '''Class representing a JoinSplit transaction.'''


class DeserializerZcash(DeserializerEquihash):
    def read_tx(self):
        header = self._read_le_uint32()
        overwintered = ((header >> 31) == 1)
        if overwintered:
            version = header & 0x7fffffff
            self.cursor += 4  # versionGroupId
        else:
            version = header

        is_overwinter_v3 = version == 3
        is_sapling_v4 = version == 4

        base_tx = TxJoinSplit(
            version,
            self._read_inputs(),    # inputs
            self._read_outputs(),   # outputs
            self._read_le_uint32()  # locktime
        )

        if is_overwinter_v3 or is_sapling_v4:
            self.cursor += 4  # expiryHeight

        has_shielded = False
        if is_sapling_v4:
            self.cursor += 8  # valueBalance
            shielded_spend_size = self._read_varint()
            self.cursor += shielded_spend_size * 384  # vShieldedSpend
            shielded_output_size = self._read_varint()
            self.cursor += shielded_output_size * 948  # vShieldedOutput
            has_shielded = shielded_spend_size > 0 or shielded_output_size > 0

        if base_tx.version >= 2:
            joinsplit_size = self._read_varint()
            if joinsplit_size > 0:
                joinsplit_desc_len = 1506 + (192 if is_sapling_v4 else 296)
                # JSDescription
                self.cursor += joinsplit_size * joinsplit_desc_len
                self.cursor += 32  # joinSplitPubKey
                self.cursor += 64  # joinSplitSig

        if is_sapling_v4 and has_shielded:
            self.cursor += 64  # bindingSig

        return base_tx


class TxTime(namedtuple("Tx", "version time inputs outputs locktime")):
    '''Class representing transaction that has a time field.'''


class DeserializerTxTime(Deserializer):
    def read_tx(self):
        return TxTime(
            self._read_le_int32(),   # version
            self._read_le_uint32(),  # time
            self._read_inputs(),     # inputs
            self._read_outputs(),    # outputs
            self._read_le_uint32(),  # locktime
        )


class TxTimeSegWit(namedtuple(
        "Tx", "version time marker flag inputs outputs witness locktime")):
    '''Class representing a SegWit transaction with time.'''


class DeserializerTxTimeSegWit(DeserializerTxTime):
    def _read_witness(self, fields):
        read_witness_field = self._read_witness_field
        return [read_witness_field() for _ in range(fields)]

    def _read_witness_field(self):
        read_varbytes = self._read_varbytes
        return [read_varbytes() for _ in range(self._read_varint())]

    def _read_tx_parts(self):
        '''Return a (deserialized TX, tx_hash, vsize) tuple.'''
        start = self.cursor
        marker = self.binary[self.cursor + 8]
        if marker:
            tx = super().read_tx()
            tx_hash = self.TX_HASH_FN(self.binary[start:self.cursor])
            return tx, tx_hash, self.binary_length

        version = self._read_le_int32()
        time = self._read_le_uint32()
        orig_ser = self.binary[start:self.cursor]

        marker = self._read_byte()
        flag = self._read_byte()

        start = self.cursor
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        orig_ser += self.binary[start:self.cursor]

        base_size = self.cursor - start
        witness = self._read_witness(len(inputs))

        start = self.cursor
        locktime = self._read_le_uint32()
        orig_ser += self.binary[start:self.cursor]
        vsize = (3 * base_size + self.binary_length) // 4

        return TxTimeSegWit(
            version, time, marker, flag, inputs, outputs, witness, locktime),\
            self.TX_HASH_FN(orig_ser), vsize

    def read_tx(self):
        return self._read_tx_parts()[0]

    def read_tx_and_hash(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, tx_hash

    def read_tx_and_vsize(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, vsize


class TxTrezarcoin(
        namedtuple("Tx", "version time inputs outputs locktime txcomment")):
    '''Class representing transaction that has a time and txcomment field.'''


class DeserializerTrezarcoin(Deserializer):

    def read_tx(self):
        version = self._read_le_int32()
        time = self._read_le_uint32()
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        if version >= 2:
            txcomment = self._read_varbytes()
        else:
            txcomment = b''
        return TxTrezarcoin(version, time, inputs, outputs, locktime,
                            txcomment)

    @staticmethod
    def blake2s_gen(data):
        keyOne = data[36:46]
        keyTwo = data[58:68]
        ntime = data[68:72]
        _nBits = data[72:76]
        _nonce = data[76:80]
        _full_merkle = data[36:68]
        _input112 = data + _full_merkle
        _key = keyTwo + ntime + _nBits + _nonce + keyOne
        # Prepare 112Byte Header
        blake2s_hash = blake2s(key=_key, digest_size=32)
        blake2s_hash.update(_input112)
        # TrezarFlips - Only for Genesis
        return ''.join(map(str.__add__, blake2s_hash.hexdigest()[-2::-2],
                           blake2s_hash.hexdigest()[-1::-2]))

    @staticmethod
    def blake2s(data):
        keyOne = data[36:46]
        keyTwo = data[58:68]
        ntime = data[68:72]
        _nBits = data[72:76]
        _nonce = data[76:80]
        _full_merkle = data[36:68]
        _input112 = data + _full_merkle
        _key = keyTwo + ntime + _nBits + _nonce + keyOne
        # Prepare 112Byte Header
        blake2s_hash = blake2s(key=_key, digest_size=32)
        blake2s_hash.update(_input112)
        # TrezarFlips
        return blake2s_hash.digest()


class DeserializerReddcoin(Deserializer):
    def read_tx(self):
        version = self._read_le_int32()
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        if version > 1:
            time = self._read_le_uint32()
        else:
            time = 0

        return TxTime(version, time, inputs, outputs, locktime)


class DeserializerEmercoin(DeserializerTxTimeSegWit):
    VERSION_AUXPOW = (1 << 8)

    def is_merged_block(self):
        start = self.cursor
        self.cursor = 0
        version = self._read_le_uint32()
        self.cursor = start
        if version & self.VERSION_AUXPOW:
            return True
        return False

    def read_header(self, static_header_size):
        '''Return the AuxPow block header bytes'''
        start = self.cursor
        version = self._read_le_uint32()
        if version & self.VERSION_AUXPOW:
            # We are going to calculate the block size then read it as bytes
            self.cursor = start
            self.cursor += static_header_size  # Block normal header
            self.read_tx()  # AuxPow transaction
            self.cursor += 32  # Parent block hash
            merkle_size = self._read_varint()
            self.cursor += 32 * merkle_size  # Merkle branch
            self.cursor += 4  # Index
            merkle_size = self._read_varint()
            self.cursor += 32 * merkle_size  # Chain merkle branch
            self.cursor += 4  # Chain index
            self.cursor += 80  # Parent block header
            header_end = self.cursor
        else:
            header_end = static_header_size
        self.cursor = start
        return self._read_nbytes(header_end)


class DeserializerBitcoinAtom(DeserializerSegWit):
    FORK_BLOCK_HEIGHT = 505888

    def read_header(self, height, static_header_size):
        '''Return the block header bytes'''
        header_len = static_header_size
        if height >= self.FORK_BLOCK_HEIGHT:
            header_len += 4  # flags
        return self._read_nbytes(header_len)


class DeserializerGroestlcoin(DeserializerSegWit):
    TX_HASH_FN = staticmethod(sha256)


class TxInputTokenPay(TxInput):
    '''Class representing a TokenPay transaction input.'''

    OP_ANON_MARKER = 0xb9
    # 2byte marker (cpubkey + sigc + sigr)
    MIN_ANON_IN_SIZE = 2 + (33 + 32 + 32)

    def _is_anon_input(self):
        return (len(self.script) >= self.MIN_ANON_IN_SIZE and
                self.script[0] == OpCodes.OP_RETURN and
                self.script[1] == self.OP_ANON_MARKER)

    def is_generation(self):
        # Transactions comming in from stealth addresses are seen by
        # the blockchain as newly minted coins. The reverse, where coins
        # are sent TO a stealth address, are seen by the blockchain as
        # a coin burn.
        if self._is_anon_input():
            return True
        return super(TxInputTokenPay, self).is_generation()


class TxInputTokenPayStealth(
        namedtuple("TxInput", "keyimage ringsize script sequence")):
    '''Class representing a TokenPay stealth transaction input.'''

    def __str__(self):
        script = self.script.hex()
        keyimage = bytes(self.keyimage).hex()
        return ("Input({}, {:d}, script={}, sequence={:d})"
                .format(keyimage, self.ringsize[1], script, self.sequence))

    def is_generation(self):
        return True

    def serialize(self):
        return b''.join((
            self.keyimage,
            self.ringsize,
            pack_varbytes(self.script),
            pack_le_uint32(self.sequence),
        ))


class DeserializerTokenPay(DeserializerTxTime):

    def _read_input(self):
        txin = TxInputTokenPay(
            self._read_nbytes(32),   # prev_hash
            self._read_le_uint32(),  # prev_idx
            self._read_varbytes(),   # script
            self._read_le_uint32(),  # sequence
        )
        if txin._is_anon_input():
            # Not sure if this is actually needed, and seems
            # extra work for no immediate benefit, but it at
            # least correctly represents a stealth input
            raw = txin.serialize()
            deserializer = Deserializer(raw)
            txin = TxInputTokenPayStealth(
                deserializer._read_nbytes(33),  # keyimage
                deserializer._read_nbytes(3),   # ringsize
                deserializer._read_varbytes(),  # script
                deserializer._read_le_uint32()  # sequence
            )
        return txin


# Decred
class TxInputDcr(namedtuple("TxInput", "prev_hash prev_idx tree sequence")):
    '''Class representing a Decred transaction input.'''

    def __str__(self):
        prev_hash = hash_to_hex_str(self.prev_hash)
        return ("Input({}, {:d}, tree={}, sequence={:d})"
                .format(prev_hash, self.prev_idx, self.tree, self.sequence))

    def is_generation(self):
        '''Test if an input is generation/coinbase like'''
        return self.prev_idx == MINUS_1 and self.prev_hash == ZERO


class TxOutputDcr(namedtuple("TxOutput", "value version pk_script")):
    '''Class representing a Decred transaction output.'''


class TxDcr(namedtuple("Tx", "version inputs outputs locktime expiry "
                             "witness")):
    '''Class representing a Decred  transaction.'''


class DeserializerDecred(Deserializer):
    @staticmethod
    def blake256(data):
        from blake256.blake256 import blake_hash
        return blake_hash(data)

    @staticmethod
    def blake256d(data):
        from blake256.blake256 import blake_hash
        return blake_hash(blake_hash(data))

    def read_tx(self):
        return self._read_tx_parts(produce_hash=False)[0]

    def read_tx_and_hash(self):
        tx, tx_hash, _vsize = self._read_tx_parts()
        return tx, tx_hash

    def read_tx_and_vsize(self):
        tx, _tx_hash, vsize = self._read_tx_parts(produce_hash=False)
        return tx, vsize

    def read_tx_block(self):
        '''Returns a list of (deserialized_tx, tx_hash) pairs.'''
        read = self.read_tx_and_hash
        txs = [read() for _ in range(self._read_varint())]
        stxs = [read() for _ in range(self._read_varint())]
        return txs + stxs

    def read_tx_tree(self):
        '''Returns a list of deserialized_tx without tx hashes.'''
        read_tx = self.read_tx
        return [read_tx() for _ in range(self._read_varint())]

    def _read_input(self):
        return TxInputDcr(
            self._read_nbytes(32),   # prev_hash
            self._read_le_uint32(),  # prev_idx
            self._read_byte(),       # tree
            self._read_le_uint32(),  # sequence
        )

    def _read_output(self):
        return TxOutputDcr(
            self._read_le_int64(),  # value
            self._read_le_uint16(),  # version
            self._read_varbytes(),  # pk_script
        )

    def _read_witness(self, fields):
        read_witness_field = self._read_witness_field
        assert fields == self._read_varint()
        return [read_witness_field() for _ in range(fields)]

    def _read_witness_field(self):
        value_in = self._read_le_int64()
        block_height = self._read_le_uint32()
        block_index = self._read_le_uint32()
        script = self._read_varbytes()
        return value_in, block_height, block_index, script

    def _read_tx_parts(self, produce_hash=True):
        start = self.cursor
        version = self._read_le_int32()
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        expiry = self._read_le_uint32()
        end_prefix = self.cursor
        witness = self._read_witness(len(inputs))

        if produce_hash:
            # TxSerializeNoWitness << 16 == 0x10000
            no_witness_header = pack_le_uint32(0x10000 | (version & 0xffff))
            prefix_tx = no_witness_header + self.binary[start+4:end_prefix]
            tx_hash = self.blake256(prefix_tx)
        else:
            tx_hash = None

        return TxDcr(
            version,
            inputs,
            outputs,
            locktime,
            expiry,
            witness
        ), tx_hash, self.cursor - start


class DeserializerSmartCash(Deserializer):

    @staticmethod
    def keccak(data):
        from Cryptodome.Hash import keccak
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(data)
        return keccak_hash.digest()

    def read_tx_and_hash(self):
        start = self.cursor
        return self.read_tx(), sha256(self.binary[start:self.cursor])


class TxBitcoinDiamond(namedtuple("Tx",
                                  "version preblockhash inputs outputs "
                                  "locktime")):
    '''Class representing a transaction.'''


class DeserializerBitcoinDiamond(Deserializer):
    bitcoin_diamond_tx_version = 12

    def read_tx(self):
        # Return a Deserialized TX.
        version = self._get_version()
        if version != self.bitcoin_diamond_tx_version:
            return Tx(
                self._read_le_int32(),  # version
                self._read_inputs(),    # inputs
                self._read_outputs(),   # outputs
                self._read_le_uint32()  # locktime
            )
        else:
            return TxBitcoinDiamond(
                self._read_le_int32(),  # version
                hash_to_hex_str(self._read_nbytes(32)),  # blockhash
                self._read_inputs(),  # inputs
                self._read_outputs(),  # outputs
                self._read_le_uint32()  # locktime
            )

    def _get_version(self):
        result, = unpack_le_int32_from(self.binary, self.cursor)
        return result


class TxBitcoinDiamondSegWit(namedtuple("Tx",
                                        "version preblockhash marker flag "
                                        "inputs outputs witness locktime")):
    '''Class representing a SegWit transaction.'''


class DeserializerBitcoinDiamondSegWit(DeserializerBitcoinDiamond,
                                       DeserializerSegWit):
    def _read_tx_parts(self):
        '''Return a (deserialized TX, tx_hash, vsize) tuple.'''
        start = self.cursor
        tx_version = self._get_version()
        if tx_version == self.bitcoin_diamond_tx_version:
            marker = self.binary[self.cursor + 4 + 32]
        else:
            marker = self.binary[self.cursor + 4]

        if marker:
            tx = super().read_tx()
            tx_hash = self.TX_HASH_FN(self.binary[start:self.cursor])
            return tx, tx_hash, self.binary_length

        # Ugh, this is nasty.
        version = self._read_le_int32()
        present_block_hash = None
        if version == self.bitcoin_diamond_tx_version:
            present_block_hash = hash_to_hex_str(self._read_nbytes(32))
        orig_ser = self.binary[start:self.cursor]

        marker = self._read_byte()
        flag = self._read_byte()

        start = self.cursor
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        orig_ser += self.binary[start:self.cursor]

        base_size = self.cursor - start
        witness = self._read_witness(len(inputs))

        start = self.cursor
        locktime = self._read_le_uint32()
        orig_ser += self.binary[start:self.cursor]
        vsize = (3 * base_size + self.binary_length) // 4

        if present_block_hash is not None:
            return TxBitcoinDiamondSegWit(
                version, present_block_hash, marker, flag, inputs, outputs,
                witness, locktime), self.TX_HASH_FN(orig_ser), vsize
        else:
            return TxSegWit(
                version, marker, flag, inputs, outputs, witness,
                locktime), self.TX_HASH_FN(orig_ser), vsize

    def read_tx(self):
        '''Return a (Deserialized TX, TX_HASH) pair.

        The hash needs to be reversed for human display; for efficiency
        we process it in the natural serialized order.
        '''
        return self._read_tx_parts()[0]


class DeserializerElectra(Deserializer):
    ELECTRA_TX_VERSION = 7

    def _get_version(self):
        result, = unpack_le_int32_from(self.binary, self.cursor)
        return result

    def read_tx(self):
        version = self._get_version()
        if version != self.ELECTRA_TX_VERSION:
            return TxTime(
                self._read_le_int32(),   # version
                self._read_le_uint32(),  # time
                self._read_inputs(),     # inputs
                self._read_outputs(),    # outputs
                self._read_le_uint32(),  # locktime
            )
        else:
            return Tx(
                self._read_le_int32(),  # version
                self._read_inputs(),    # inputs
                self._read_outputs(),   # outputs
                self._read_le_uint32()  # locktime
            )


class DeserializerECCoin(Deserializer):
    def read_tx(self):
        tx_version = self._read_le_int32()
        tx = TxTime(
            tx_version,
            self._read_le_uint32(),
            self._read_inputs(),
            self._read_outputs(),
            self._read_le_uint32(),
        )

        if tx_version > 1:
            self.cursor += 32

        return tx


class DeserializerZcoin(Deserializer):
    def _read_input(self):
        tx_input = TxInput(
            self._read_nbytes(32),   # prev_hash
            self._read_le_uint32(),  # prev_idx
            self._read_varbytes(),   # script
            self._read_le_uint32()   # sequence
        )

        if tx_input.prev_idx == MINUS_1 and tx_input.prev_hash == ZERO:
            return tx_input

        if tx_input.script[0] == 0xc4:  # This is a Sigma spend - mimic a generation tx
            return TxInput(
                ZERO,
                MINUS_1,
                tx_input.script,
                tx_input.sequence
            )

        return tx_input


class DeserializerXaya(DeserializerSegWit, DeserializerAuxPow):
    """Deserializer class for the Xaya network

    The main difference to other networks is the changed format of the
    block header with "triple purpose mining", see
    https://github.com/xaya/xaya/blob/master/doc/xaya/mining.md.

    This builds upon classic auxpow, but has a modified serialisation format
    that we have to implement here."""

    MM_FLAG = 0x80

    def read_header(self, static_header_size):
        """Reads in the full block header (including PoW data)"""

        # We first calculate the dynamic size of the block header, and then
        # read in all the data in the final step.
        start = self.cursor

        self.cursor += static_header_size  # Normal block header

        algo = self._read_byte()
        self._read_le_uint32()  # nBits

        if algo & self.MM_FLAG:
            self.read_auxpow()
        else:
            self.cursor += static_header_size  # Fake header

        end = self.cursor
        self.cursor = start
        return self._read_nbytes(end - start)


@dataclass
class TxPIVX:
    '''Class representing a PIVX transaction.'''
    __slots__ = 'version', "txtype", 'inputs', 'outputs', 'locktime'
    version: int
    txtype: int
    inputs: Sequence['TxInput']
    outputs: Sequence['TxOutput']
    locktime: int

    def serialize(self):
        return b''.join((
            pack_le_uint16(self.version),
            pack_le_uint16(self.txtype),
            pack_varint(len(self.inputs)),
            b''.join(tx_in.serialize() for tx_in in self.inputs),
            pack_varint(len(self.outputs)),
            b''.join(tx_out.serialize() for tx_out in self.outputs),
            pack_le_uint32(self.locktime)
        ))


class DeserializerPIVX(Deserializer):
    def read_tx(self):
        header = self._read_le_uint32()
        tx_type = header >> 16  # DIP2 tx type
        if tx_type:
            version = header & 0x0000ffff
        else:
            version = header

        if tx_type and version < 3:
            version = header
            tx_type = 0

        base_tx = TxPIVX(
            version,
            tx_type,
            self._read_inputs(),  # inputs
            self._read_outputs(),  # outputs
            self._read_le_uint32()  # locktime
        )

        if version >= 3:  # >= sapling
            self._read_varint()
            self.cursor += 8  # valueBalance
            shielded_spend_size = self._read_varint()
            self.cursor += shielded_spend_size * 384  # vShieldedSpend
            shielded_output_size = self._read_varint()
            self.cursor += shielded_output_size * 948  # vShieldedOutput
            self.cursor += 64  # bindingSig
            if (tx_type > 0):
                self.cursor += 2  # extraPayload

        return base_tx


class LBRYBlockProcessor(BlockProcessor):

    def __init__(self, *args, **kwargs):
        self.claim_cache = {}
        self.claims_for_name_cache = {}
        self.claims_signed_by_cert_cache = {}
        self.outpoint_to_claim_id_cache = {}
        self.claims_db = self.names_db = self.signatures_db = self.outpoint_to_claim_id_db = self.claim_undo_db = None
        super().__init__(*args, **kwargs)

        # stores deletes not yet flushed to disk
        self.pending_abandons = {}
        self.should_validate_signatures = self.env.boolean('VALIDATE_CLAIM_SIGNATURES', False)

    def open_dbs(self):
        super().open_dbs()

        for for_sync in [False, True]:
            if self.claims_db:
                if self.claims_db.for_sync == for_sync:
                    return
                self.claims_db.close()
                self.names_db.close()
                self.signatures_db.close()
                self.outpoint_to_claim_id_db.close()
                self.claim_undo_db.close()
            self.claims_db = self.db_class('claims', for_sync)
            self.names_db = self.db_class('names', for_sync)
            self.signatures_db = self.db_class('signatures', for_sync)
            self.outpoint_to_claim_id_db = self.db_class('outpoint_claim_id', for_sync)
            self.claim_undo_db = self.db_class('claim_undo', for_sync)

    def flush(self, flush_utxos=False):
        # flush claims together with utxos as they are parsed together
        self.batched_flush_claims()
        return super().flush(flush_utxos=flush_utxos)

    def batched_flush_claims(self):
        with self.claims_db.write_batch() as claims_batch:
            with self.names_db.write_batch() as names_batch:
                with self.signatures_db.write_batch() as signed_claims_batch:
                    with self.outpoint_to_claim_id_db.write_batch() as outpoint_batch:
                        self.flush_claims(claims_batch, names_batch, signed_claims_batch,
                                          outpoint_batch)

    def flush_claims(self, batch, names_batch, signed_claims_batch, outpoint_batch):
        flush_start = time.time()
        write_claim, write_name, write_cert = batch.put, names_batch.put, signed_claims_batch.put
        write_outpoint = outpoint_batch.put
        delete_claim, delete_outpoint, delete_name = batch.delete, outpoint_batch.delete, names_batch.delete
        delete_cert = signed_claims_batch.delete
        for claim_id, outpoints in self.pending_abandons.items():
            claim = self.get_claim_info(claim_id)
            self.remove_claim_for_name(claim.name, claim_id)
            if claim.cert_id:
                self.remove_claim_from_certificate_claims(claim.cert_id, claim_id)
            self.remove_certificate(claim_id)
            self.claim_cache[claim_id] = None
            for txid, tx_index in outpoints:
                self.put_claim_id_for_outpoint(txid, tx_index, None)
        for key, claim in self.claim_cache.items():
            if claim:
                write_claim(key, claim)
            else:
                delete_claim(key)
        for name, claims in self.claims_for_name_cache.items():
            if not claims:
                delete_name(name)
            else:
                write_name(name, msgpack.dumps(claims))
        for cert_id, claims in self.claims_signed_by_cert_cache.items():
            if not claims:
                delete_cert(cert_id)
            else:
                write_cert(cert_id, msgpack.dumps(claims))
        for key, claim_id in self.outpoint_to_claim_id_cache.items():
            if claim_id:
                write_outpoint(key, claim_id)
            else:
                delete_outpoint(key)

        self.claim_cache = {}
        self.claims_for_name_cache = {}
        self.claims_signed_by_cert_cache = {}
        self.outpoint_to_claim_id_cache = {}
        self.pending_abandons = {}

    def assert_flushed(self):
        super().assert_flushed()
        assert not self.claim_cache
        assert not self.claims_for_name_cache
        assert not self.claims_signed_by_cert_cache
        assert not self.outpoint_to_claim_id_cache
        assert not self.pending_abandons

    def advance_blocks(self, blocks):
        # save height, advance blocks as usual, then hook our claim tx processing
        height = self.height + 1
        super().advance_blocks(blocks)
        pending_undo = []
        for index, block in enumerate(blocks):
            undo = self.advance_claim_txs(block.transactions, height + index)
            pending_undo.append((height+index, undo,))
        with self.claim_undo_db.write_batch() as writer:
            for height, undo_info in pending_undo:
                writer.put(struct.pack(">I", height), msgpack.dumps(undo_info))

    def spend_utxo(self, tx_hash, tx_idx):
        # this is called during electrumx tx advance, we gather spents in the process to avoid looping again
        result = super().spend_utxo(tx_hash, tx_idx)
        return result

    def advance_claim_txs(self, txs, height):
        # TODO: generate claim undo info!
        undo_info = []
        add_undo = undo_info.append
        update_inputs = set()
        for tx, txid in txs:
            update_inputs.clear()
            if tx.has_claims:
                for index, output in enumerate(tx.outputs):
                    claim = output.claim
                    if isinstance(claim, NameClaim):
                        add_undo(self.advance_claim_name_transaction(output, height, txid, index))
                    elif isinstance(claim, ClaimUpdate):
                        update_input = self.get_update_input(claim, tx.inputs)
                        if update_input:
                            update_inputs.add(update_input)
                            add_undo(self.advance_update_claim(output, height, txid, index))
                        else:
                            info = (hash_to_hex_str(txid), hash_to_hex_str(claim.claim_id),)
                    elif isinstance(claim, ClaimSupport):
                        self.advance_support(claim, txid, index, height, output.value)
            for txin in tx.inputs:
                if txin not in update_inputs:
                    abandoned_claim_id = self.abandon_spent(txin.prev_hash, txin.prev_idx)
                    if abandoned_claim_id:
                        add_undo((abandoned_claim_id, self.get_claim_info(abandoned_claim_id)))
        return undo_info

    def advance_update_claim(self, output, height, txid, nout):
        claim_id = output.claim.claim_id
        claim_info = self.claim_info_from_output(output, txid, nout, height)
        old_claim_info = self.get_claim_info(claim_id)
        self.put_claim_id_for_outpoint(old_claim_info.txid, old_claim_info.nout, None)
        if old_claim_info.cert_id:
            self.remove_claim_from_certificate_claims(old_claim_info.cert_id, claim_id)
        if claim_info.cert_id:
            self.put_claim_id_signed_by_cert_id(claim_info.cert_id, claim_id)
        self.put_claim_info(claim_id, claim_info)
        self.put_claim_id_for_outpoint(txid, nout, claim_id)
        return claim_id, old_claim_info

    def advance_claim_name_transaction(self, output, height, txid, nout):
        claim_id = claim_id_hash(txid, nout)
        claim_info = self.claim_info_from_output(output, txid, nout, height)
        if claim_info.cert_id:
            self.put_claim_id_signed_by_cert_id(claim_info.cert_id, claim_id)
        self.put_claim_info(claim_id, claim_info)
        self.put_claim_for_name(claim_info.name, claim_id)
        self.put_claim_id_for_outpoint(txid, nout, claim_id)
        return claim_id, None

    def backup_from_undo_info(self, claim_id, undo_claim_info):
        """
        Undo information holds a claim state **before** a transaction changes it
        There are 4 possibilities when processing it, of which only 3 are valid ones:
         1. the claim is known and the undo info has info, it was an update
         2. the claim is known and the undo info doesn't hold any info, it was claimed
         3. the claim in unknown and the undo info has info, it was abandoned
         4. the claim is unknown and the undo info does't hold info, error!
        """

        undo_claim_info = ClaimInfo(*undo_claim_info) if undo_claim_info else None
        current_claim_info = self.get_claim_info(claim_id)
        if current_claim_info and undo_claim_info:
            # update, remove current claim
            self.remove_claim_id_for_outpoint(current_claim_info.txid, current_claim_info.nout)
            if current_claim_info.cert_id:
                self.remove_claim_from_certificate_claims(current_claim_info.cert_id, claim_id)
        elif current_claim_info and not undo_claim_info:
            # claim, abandon it
            self.abandon_spent(current_claim_info.txid, current_claim_info.nout)
        elif not current_claim_info and undo_claim_info:
            # abandon, reclaim it (happens below)
            pass
        else:
            # should never happen, unless the database got into an inconsistent state
            raise Exception("Unexpected situation occurred on backup, this means the database is inconsistent. "
                            "Please report. Resetting the data folder (reindex) solves it for now.")
        if undo_claim_info:
            self.put_claim_info(claim_id, undo_claim_info)
            if undo_claim_info.cert_id:
                cert_id = self._checksig(undo_claim_info.name, undo_claim_info.value, undo_claim_info.address)
                self.put_claim_id_signed_by_cert_id(cert_id, claim_id)
            self.put_claim_for_name(undo_claim_info.name, claim_id)
            self.put_claim_id_for_outpoint(undo_claim_info.txid, undo_claim_info.nout, claim_id)

    def backup_txs(self, txs):
        undo_info = msgpack.loads(self.claim_undo_db.get(struct.pack(">I", self.height)), use_list=False)
        for claim_id, undo_claim_info in reversed(undo_info):
            self.backup_from_undo_info(claim_id, undo_claim_info)
        return super().backup_txs(txs)

    def backup_blocks(self, raw_blocks):
        self.batched_flush_claims()
        super().backup_blocks(raw_blocks=raw_blocks)
        self.batched_flush_claims()

    def shutdown(self, executor):
        self.batched_flush_claims()
        return super().shutdown(executor=executor)

    def backup_claim_name(self, txid, nout):
        self.abandon_spent(txid, nout)

    def advance_support(self, claim_support, txid, nout, height, amount):
        # TODO: check for more controller claim rules, like takeover or ordering
        pass

    def claim_info_from_output(self, output, txid, nout, height):
        amount = output.value
        address = self.coin.address_from_script(output.pk_script)
        name, value, cert_id = output.claim.name, output.claim.value, None
        assert txid and address
        cert_id = self._checksig(name, value, address)
        return ClaimInfo(name, value, txid, nout, amount, address, height, cert_id)

    def _checksig(self, name, value, address):
        try:
            parse_lbry_uri(name.decode())  # skip invalid names
            cert_id = Claim.FromString(value).publisherSignature.certificateId[::-1] or None
            if not self.should_validate_signatures:
                return cert_id
            if cert_id:
                cert_claim = self.get_claim_info(cert_id)
                if cert_claim:
                    certificate = smart_decode(cert_claim.value)
                    claim_dict = smart_decode(value)
                    claim_dict.validate_signature(address, certificate)
                    return cert_id
        except Exception as e:
            pass

    def get_update_input(self, claim, inputs):
        claim_id = claim.claim_id
        claim_info = self.get_claim_info(claim_id)
        if not claim_info:
            return False
        for input in inputs:
            if input.prev_hash == claim_info.txid and input.prev_idx == claim_info.nout:
                return input
        return False

    def abandon_spent(self, tx_hash, tx_idx):
        claim_id = self.get_claim_id_from_outpoint(tx_hash, tx_idx)
        if claim_id:
            self.pending_abandons.setdefault(claim_id, []).append((tx_hash, tx_idx,))
            return claim_id

    def put_claim_id_for_outpoint(self, tx_hash, tx_idx, claim_id):
        self.outpoint_to_claim_id_cache[tx_hash + struct.pack('>I', tx_idx)] = claim_id

    def remove_claim_id_for_outpoint(self, tx_hash, tx_idx):
        self.outpoint_to_claim_id_cache[tx_hash + struct.pack('>I', tx_idx)] = None

    def get_claim_id_from_outpoint(self, tx_hash, tx_idx):
        key = tx_hash + struct.pack('>I', tx_idx)
        return self.outpoint_to_claim_id_cache.get(key) or self.outpoint_to_claim_id_db.get(key)

    def get_claims_for_name(self, name):
        if name in self.claims_for_name_cache: return self.claims_for_name_cache[name]
        db_claims = self.names_db.get(name)
        return msgpack.loads(db_claims) if db_claims else {}

    def put_claim_for_name(self, name, claim_id):
        claims = self.get_claims_for_name(name)
        claims.setdefault(claim_id, max(claims.values() or [0]) + 1)
        self.claims_for_name_cache[name] = claims

    def remove_claim_for_name(self, name, claim_id):
        claims = self.get_claims_for_name(name)
        claim_n = claims.pop(claim_id)
        for claim_id, number in claims.items():
            if number > claim_n:
                claims[claim_id] = number - 1
        self.claims_for_name_cache[name] = claims

    def get_signed_claim_ids_by_cert_id(self, cert_id):
        if cert_id in self.claims_signed_by_cert_cache: return self.claims_signed_by_cert_cache[cert_id]
        db_claims = self.signatures_db.get(cert_id)
        return msgpack.loads(db_claims, use_list=True) if db_claims else []

    def put_claim_id_signed_by_cert_id(self, cert_id, claim_id):
        certs = self.get_signed_claim_ids_by_cert_id(cert_id)
        certs.append(claim_id)
        self.claims_signed_by_cert_cache[cert_id] = certs

    def remove_certificate(self, cert_id):
        self.claims_signed_by_cert_cache[cert_id] = []

    def remove_claim_from_certificate_claims(self, cert_id, claim_id):
        certs = self.get_signed_claim_ids_by_cert_id(cert_id)
        if claim_id in certs:
            certs.remove(claim_id)
        self.claims_signed_by_cert_cache[cert_id] = certs

    def get_claim_info(self, claim_id):
        serialized = self.claim_cache.get(claim_id) or self.claims_db.get(claim_id)
        return ClaimInfo.from_serialized(serialized) if serialized else None

    def put_claim_info(self, claim_id, claim_info):
        self.claim_cache[claim_id] = claim_info.serialized


def claim_id_hash(txid, n):
    # TODO: This should be in lbryschema
    packed = txid + struct.pack('>I', n)
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(packed).digest())
    return md.digest()
