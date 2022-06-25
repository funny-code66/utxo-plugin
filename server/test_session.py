import asyncio
import json
import unittest
from electrumx.lib.hash import sha256, hash_to_hex_str

from server.session import get_history


def make_vin(txid, n):
    return {
        'txid': txid,
        'vout': n,
    }


def make_vout(amount, n, vout_addresses):
    return {
        'n': n,
        'scriptPubKey': make_script_pubkey(vout_addresses),
        'value': amount,
    }


def make_script_pubkey(vout_addresses):
    return {
        'type': 'pubkeyhash',
        'addresses': vout_addresses,
    }


def make_tx(txhash, vins, vouts, blockhash):
    return {
        'txhash': txhash,
        'txid': hash_to_hex_str(txhash),
        'vin': vins,
        'vout': vouts,
        'confirmations': 1001,
        'blockhash': blockhash,
        'blocktime': 1605765456,
    }


def hash_t(p):
    return sha256(bytes(p, encoding='utf8'))


# lookup txid should match hash_t('txhash_n') in sample data
tx_lookup = {
    'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a': make_tx(hash_t('txhash1'), [make_vin('0000000000000000000000000000000000000000000000000000000000000000', 0)], [make_vout(1000, 0, ['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm']), make_vout(10, 1, ['yEV4bGVBqzJSiWv5xgJCoJwZzTgi5fYoCD'])], '312bc8c82eb2d5a09fbbcdbdcb0cab37fb66d61b97001b241ad23814746542d2'),
    '875e933ad470ef78f1ad0f9ed020f9787e22604b26d0cedd3d0c744446fd47de': make_tx(hash_t('txhash2'), [make_vin('f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a', 0)], [make_vout(900, 0, ['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm']), make_vout(10, 1, ['yEV4bGVBqzJSiWv5xgJCoJwZzTgi5fYoCD'])], '8ca920914f8e60622597b3c147d005283415df9b193e4502fd762b21602b07fd'),
    '491eb677bc65aec4bfa01343971c6c1335e98083415f6484431e10085ce8f8bc': make_tx(hash_t('txhash3'), [make_vin('875e933ad470ef78f1ad0f9ed020f9787e22604b26d0cedd3d0c744446fd47de', 0)], [make_vout(800, 0, ['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm']), make_vout(10, 1, ['yEV4bGVBqzJSiWv5xgJCoJwZzTgi5fYoCD'])], '408b97b9731f4e0263548906641e346fb253a9316dc32fb69dd10bb6ebb71a5e'),
    '9727c697a18404a1334dcb7d6d60cb2da43c021b96327a44e0d8e0e6291dcbe1': make_tx(hash_t('txhash4'), [make_vin('491eb677bc65aec4bfa01343971c6c1335e98083415f6484431e10085ce8f8bc', 0)], [make_vout(700, 0, ['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm']), make_vout(10, 1, ['yEV4bGVBqzJSiWv5xgJCoJwZzTgi5fYoCD'])], 'e4599bf4b81d34b4cd58950f360acab719e4b625b3c4198f0075d99c4c3b6991'),
    '0b440a548408b5b3d064b8a3f42f01084cfb025db6b49d858e3e4066c23288f8': make_tx(hash_t('txhash5'), [make_vin('9727c697a18404a1334dcb7d6d60cb2da43c021b96327a44e0d8e0e6291dcbe1', 0)], [make_vout(600, 0, ['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm']), make_vout(10, 1, ['yEV4bGVBqzJSiWv5xgJCoJwZzTgi5fYoCD'])], 'aae3f13580b56957617535a46cfad6b76ad2a2ea8c4cad635460a56f4ee29a6f'),
    '8ce220fca530a65dbe4ae2e0940708cfeb9a2546c9caec494c98ec60b4e65e45': make_tx(hash_t('txhash6'), [make_vin('0b440a548408b5b3d064b8a3f42f01084cfb025db6b49d858e3e4066c23288f8', 0)], [make_vout(500, 0, ['yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy']), make_vout(10, 1, ['yF4d7VrFUtr4h1rNEhwdNfrEQXbNvdCR8v'])], '3ce8c3e5ea06a95fc9447ca9d5c49077a6088448b100a6b15af4f67231217520'),
    'e39921b213ff2640d619f96c2264cb2e82fc6e2c6d927d0f59645cfd7cfb9c64': make_tx(hash_t('txhash7'), [make_vin('8ce220fca530a65dbe4ae2e0940708cfeb9a2546c9caec494c98ec60b4e65e45', 0)], [make_vout(400, 0, ['yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy']), make_vout(10, 1, ['yF4d7VrFUtr4h1rNEhwdNfrEQXbNvdCR8v'])], '9dba1be0d19bae77bd942ac6cf6d05ad76c4a35c9ef01ffe1848c2009b75f541'),
    'c7aab36642676d7da61970bcce2c7c6057cd623d8651a62157f774ac02fd1360': make_tx(hash_t('txhash8'), [make_vin('e39921b213ff2640d619f96c2264cb2e82fc6e2c6d927d0f59645cfd7cfb9c64', 0)], [make_vout(300, 0, ['yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy']), make_vout(10, 1, ['yF4d7VrFUtr4h1rNEhwdNfrEQXbNvdCR8v'])], '3f6545c69e56121b0d8a4c72af728fd28c0d8c4a2e67085c8e6212a99b81b299'),
    '64ff66741cd1d37669f7f3b015f69c78878417dc4e31c1821d85ad54bc1e0de4': make_tx(hash_t('txhash9'), [make_vin('c7aab36642676d7da61970bcce2c7c6057cd623d8651a62157f774ac02fd1360', 0)], [make_vout(200, 0, ['yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy']), make_vout(10, 1, ['yF4d7VrFUtr4h1rNEhwdNfrEQXbNvdCR8v'])], 'a7a603cee2518059946b8b4eabb6406be407421ab61f1301659faf56ace2a371'),
    '3bc3262ea3ae1e7b041ca050a32a4eaed1d899834a8b3f415307567762695b15': make_tx(hash_t('txhash10'), [make_vin('64ff66741cd1d37669f7f3b015f69c78878417dc4e31c1821d85ad54bc1e0de4', 0)], [make_vout(100, 0, ['yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy']), make_vout(10, 1, ['yF4d7VrFUtr4h1rNEhwdNfrEQXbNvdCR8v'])], '8047e0f6ed7378a915664116de384d8616c6b34cb2ba825444c0d1da5c6d7f45'),
    'befc41488710a2836832a481cf5cdb9e6fe31f8ef91ba691d177030e58ee1c30': make_tx(hash_t('txhash11'), [make_vin('3bc3262ea3ae1e7b041ca050a32a4eaed1d899834a8b3f415307567762695b15', 0)], [make_vout(90, 0, ['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm']), make_vout(5, 1, ['yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy'])], 'a77fe3be40af7476e78a58253a506979fcba53957879f230c8760858fb4912ea'),
    '14bd21813a10e6a8db5f2f48fd40eb6b8be91e0013f2239f80360f2b1d688fbe': make_tx(hash_t('txhash12'), [make_vin('befc41488710a2836832a481cf5cdb9e6fe31f8ef91ba691d177030e58ee1c30', 0)], [make_vout(80, 0, ['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm']), make_vout(5, 1, ['yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy'])], '8970ca946b094650279c1353138479bb77377ff9062773c6a1db6c5fdfad9ffe'),
    '007c9e9a42cdba115eabbe557d45dcf09cb6fd61dfa7c8db40a4f25aa34a0d48': make_tx(hash_t('txhash13'), [make_vin('14bd21813a10e6a8db5f2f48fd40eb6b8be91e0013f2239f80360f2b1d688fbe', 0)], [make_vout(70, 0, ['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm']), make_vout(5, 1, ['yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy'])], '69326b38b04510184deaae653a05a6035b9fb2ba981e94c3008bf1bf9d2aade2'),
    'a073fc4c52532632b98bd3d30c93970d3d0cf2cabcf85848aedeb2112cc3d0bd': make_tx(hash_t('txhash14'), [make_vin('007c9e9a42cdba115eabbe557d45dcf09cb6fd61dfa7c8db40a4f25aa34a0d48', 0)], [make_vout(60, 0, ['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm']), make_vout(5, 1, ['yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy'])], 'ccc2dc181c864552cbddedfad5c988ff704035b83a0c895509d1d4fff2fb30e9'),
    '07202b7da9b1847deda07f15c2c8c0be0400575a39a6fe1dde11bbac8c028dbc': make_tx(hash_t('txhash15'), [make_vin('a073fc4c52532632b98bd3d30c93970d3d0cf2cabcf85848aedeb2112cc3d0bd', 0)], [make_vout(50, 0, ['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm']), make_vout(5, 1, ['yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy'])], '5527a3b0bd86061d1a733e1a49ea562d73d20c59f58a2b4d578ea0eefcdfd64a'),
}


def address_to_hashX(address):
    return hash_t(address)


def session_mgr(address_to_hash_x, p_tx_lookup):
    async def limited_history(hash_x):
        r = set()
        def add_r(vout):
            if 'addresses' not in vout['scriptPubKey']:
                return
            addr_list = []
            if isinstance(vout['scriptPubKey']['addresses'], list):
                addr_list = vout['scriptPubKey']['addresses']
            elif isinstance(vout['scriptPubKey']['addresses'], str):
                addr_list = [vout['scriptPubKey']['addresses']]
            for address in addr_list:
                if address_to_hash_x(address) == hash_x:
                    r.add((v['txhash'], 1))
        for k, v in p_tx_lookup.items():
            for vout in v['vout']:
                add_r(vout)
            for vin in v['vin']:
                tx = await transaction_get(p_tx_lookup)(vin['txid'])
                if not tx:
                    continue
                for vout in tx['vout']:
                    add_r(vout)

        return list(r), 0
    return type('obj', (object,), {'limited_history': limited_history})


def bump_cost(cost):
    return


def transaction_get(p_tx_lookup):
    async def tx_get(hash_x, verbose=False):
        if hash_x in p_tx_lookup:
            return p_tx_lookup[hash_x]
        else:
            return None
    return tx_get


def logger():
    return type('obj', (object,), {'info': lambda arg: print(arg + '\n')})


def async_test(f):
    def wrapper(*args, **kwargs):
        coro = asyncio.coroutine(f)
        future = coro(*args, **kwargs)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(future)
    return wrapper


class TestGetHistory(unittest.TestCase):
    @async_test
    async def test_get_history_valid_sendreceive(self):
        """The exact numbers here are based on manual transaction counts in the sample data"""
        data = await get_history(['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup), bump_cost, transaction_get(tx_lookup), logger())
        self.assertEqual(2, len(list(filter(lambda tx: tx['category'] == 'receive', data))), 'expecting receive transactions for single address yDaL')
        self.assertEqual(10, len(list(filter(lambda tx: tx['category'] == 'send', data))), 'expecting send transactions for single address yDaL')
        data = await get_history(['yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup), bump_cost, transaction_get(tx_lookup), logger())
        self.assertEqual(5, len(list(filter(lambda tx: tx['category'] == 'receive', data))), 'expecting receive transactions for single address yDg7')
        self.assertEqual(5, len(list(filter(lambda tx: tx['category'] == 'send', data))), 'expecting send transactions for single address yDaL')
        data = await get_history(['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm', 'yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup), bump_cost, transaction_get(tx_lookup), logger())
        self.assertEqual(7, len(list(filter(lambda tx: tx['category'] == 'receive', data))), 'expecting receive transactions for multiple addresses')
        self.assertEqual(9, len(list(filter(lambda tx: tx['category'] == 'send', data))), 'expecting send transactions for multiple addresses')

    @async_test
    async def test_get_history_props(self):
        data = await get_history(['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup), bump_cost, transaction_get(tx_lookup), logger())
        data = sorted(data, key=lambda d: d['amount'], reverse=False)

        # check props
        self.assertIn('address', data[0], 'missing property')
        self.assertIn('amount', data[0], 'missing property')
        self.assertIn('fee', data[0], 'missing property')
        self.assertIn('vout', data[0], 'missing property')
        self.assertIn('category', data[0], 'missing property')
        self.assertIn('confirmations', data[0], 'missing property')
        self.assertIn('blockhash', data[0], 'missing property')
        self.assertIn('blocktime', data[0], 'missing property')
        self.assertIn('time', data[0], 'missing property')
        self.assertIn('txid', data[0], 'missing property')
        self.assertIn('from_addresses', data[0], 'missing property')
        for tx in data:
            self.assertIn(tx['category'], ['send', 'receive'], 'expecting category to be send or receive')

        # check types
        self.assertIs(str,   type(data[1]['address']), 'expecting str')
        self.assertIs(float, type(data[1]['amount']), 'expecting float')
        self.assertIs(float, type(data[1]['fee']), 'expecting float')
        self.assertIs(int,   type(data[1]['vout']), 'expecting int')
        self.assertIs(str,   type(data[1]['category']), 'expecting str')
        self.assertIs(int,   type(data[1]['confirmations']), 'expecting int')
        self.assertIs(str,   type(data[1]['blockhash']), 'expecting str')
        self.assertIs(int,   type(data[1]['blocktime']), 'expecting int')
        self.assertIs(int,   type(data[1]['time']), 'expecting int')
        self.assertIs(str,   type(data[1]['txid']), 'expecting str')
        self.assertIs(list,  type(data[1]['from_addresses']), 'expecting string list')
        self.assertIs(str,   type(data[1]['from_addresses'][0]), 'expecting string')

    @async_test
    async def test_get_history_no_dups(self):
        data = await get_history(['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup), bump_cost, transaction_get(tx_lookup), logger())
        dups = {}
        for d in data:
            unique_id = (d['txid'], d['vout'], d['category'])
            if unique_id in dups:
                dups[unique_id] += 1
            else:
                dups[unique_id] = 1
        for k, v in dups.items():
            self.assertEqual(1, v, 'expecting no duplicates')

    @async_test
    async def test_get_history_fees(self):
        """fee = total_vins - total_vouts
        The fee amount is assigned to the largest vin tx with an address
        that belongs to us. If address is not ours no fee is recorded."""
        my_address = 'yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm'
        data = await get_history([my_address], address_to_hashX, session_mgr(address_to_hashX, tx_lookup), bump_cost, transaction_get(tx_lookup), logger())
        def debug_sort(a):
            return a['amount']
        data.sort(key=debug_sort, reverse=False)
        for d in data:
            tx = await transaction_get(tx_lookup)(d['txid'])
            total_vin_amount = 0
            total_vout_amount = 0
            my_total_vin_amount = 0
            other_biggest_amount = 0
            other_biggest_address = ''
            for vout in tx['vout']:
                amount = vout['value']
                total_vout_amount += amount
                addr = vout['scriptPubKey']['addresses'][0]
                if amount > other_biggest_amount and addr != my_address:
                    other_biggest_amount = amount
                    other_biggest_address = addr
            for vin in tx['vin']:
                tx_prev = await transaction_get(tx_lookup)(vin['txid'])
                if not tx_prev:
                    continue
                amount = tx_prev['vout'][vin['vout']]['value']
                total_vin_amount += amount
                for addr in tx_prev['vout'][vin['vout']]['scriptPubKey']['addresses']:
                    if addr == my_address:
                        my_total_vin_amount += amount
                        break
            fees = total_vin_amount - total_vout_amount
            # Check that a transaction exists with proper fee designations
            # Fee should be assigned to the largest tx marked as send.
            # Expecting fees and amount on 'send' category tx to be negative
            # values.
            if my_total_vin_amount > 0:
                expecting = None
                expecting_only_one = 0
                expecting_zero_fees = 0
                for d2 in data:
                    if d['txid'] == d2['txid'] and d2['fee'] == -fees and d2['amount'] == -other_biggest_amount \
                            and d2['address'] == other_biggest_address and d2['category'] == 'send':
                        expecting = d2
                        expecting_only_one += 1
                    elif d['txid'] == d2['txid'] and d2['fee'] == -fees:
                        expecting_zero_fees += 1
                self.assertIsNotNone(expecting, 'expecting tx with proper fee designation on largest send amount')
                self.assertEqual(1, expecting_only_one, 'expecting only 1 transaction')
                self.assertEqual(0, expecting_zero_fees, 'expecting 0 fees to be on other transactions')

    @async_test
    async def test_get_history_amounts(self):
        data = await get_history(['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup), bump_cost, transaction_get(tx_lookup), logger())
        actual_data_txs_ids = set(list(map(lambda tx: tx['txid'], data)))
        expecting_txs_ids = [
            'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a',
            '875e933ad470ef78f1ad0f9ed020f9787e22604b26d0cedd3d0c744446fd47de',
            '491eb677bc65aec4bfa01343971c6c1335e98083415f6484431e10085ce8f8bc',
            '9727c697a18404a1334dcb7d6d60cb2da43c021b96327a44e0d8e0e6291dcbe1',
            '0b440a548408b5b3d064b8a3f42f01084cfb025db6b49d858e3e4066c23288f8',
            '8ce220fca530a65dbe4ae2e0940708cfeb9a2546c9caec494c98ec60b4e65e45',
            'befc41488710a2836832a481cf5cdb9e6fe31f8ef91ba691d177030e58ee1c30',
            '14bd21813a10e6a8db5f2f48fd40eb6b8be91e0013f2239f80360f2b1d688fbe',
            '007c9e9a42cdba115eabbe557d45dcf09cb6fd61dfa7c8db40a4f25aa34a0d48',
            'a073fc4c52532632b98bd3d30c93970d3d0cf2cabcf85848aedeb2112cc3d0bd',
            '07202b7da9b1847deda07f15c2c8c0be0400575a39a6fe1dde11bbac8c028dbc',
        ]
        # Expecting all the txs in the data
        for txid in expecting_txs_ids:
            self.assertGreaterEqual(len(list(filter(lambda tx: tx['txid'] == txid, data))), 1)

            # Assert send/receive amounts
            txs = list(filter(lambda tx: tx['txid'] == txid, data))

            if txid == 'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('receive', tx1['category'], 'expecting receive tx')
                self.assertEqual('yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm', tx1['address'], 'only expecting receive address')
                self.assertEqual(1000, tx1['amount'], 'expecting receive amount to equal')
                self.assertEqual(0, tx1['fee'], 'expecting receive fee to equal')
            elif txid == '875e933ad470ef78f1ad0f9ed020f9787e22604b26d0cedd3d0c744446fd47de':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('send', tx1['category'], 'only expecting send txs to foreign address')
                self.assertEqual('yEV4bGVBqzJSiWv5xgJCoJwZzTgi5fYoCD', tx1['address'], 'only expecting send txs to foreign address')
                self.assertEqual(-10, tx1['amount'], 'expecting send amount to equal')
                self.assertEqual(-90, tx1['fee'], 'expecting send fee to equal')
            elif txid == '491eb677bc65aec4bfa01343971c6c1335e98083415f6484431e10085ce8f8bc':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('send', tx1['category'], 'only expecting send txs to foreign address')
                self.assertEqual('yEV4bGVBqzJSiWv5xgJCoJwZzTgi5fYoCD', tx1['address'], 'only expecting send txs to foreign address')
                self.assertEqual(-10, tx1['amount'], 'expecting send amount to equal')
                self.assertEqual(-90, tx1['fee'], 'expecting send fee to equal')
            elif txid == '9727c697a18404a1334dcb7d6d60cb2da43c021b96327a44e0d8e0e6291dcbe1':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('send', tx1['category'], 'only expecting send txs to foreign address')
                self.assertEqual('yEV4bGVBqzJSiWv5xgJCoJwZzTgi5fYoCD', tx1['address'], 'only expecting send txs to foreign address')
                self.assertEqual(-10, tx1['amount'], 'expecting send amount to equal')
                self.assertEqual(-90, tx1['fee'], 'expecting send fee to equal')
            elif txid == '0b440a548408b5b3d064b8a3f42f01084cfb025db6b49d858e3e4066c23288f8':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('send', tx1['category'], 'only expecting send txs to foreign address')
                self.assertEqual('yEV4bGVBqzJSiWv5xgJCoJwZzTgi5fYoCD', tx1['address'], 'only expecting send txs to foreign address')
                self.assertEqual(-10, tx1['amount'], 'expecting send amount to equal')
                self.assertEqual(-90, tx1['fee'], 'expecting send fee to equal')
            elif txid == '8ce220fca530a65dbe4ae2e0940708cfeb9a2546c9caec494c98ec60b4e65e45':
                self.assertEqual(2, len(txs), 'expecting transaction count')
                tx1 = list(filter(lambda tx: tx['address'] == 'yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy', txs))[0]
                tx2 = list(filter(lambda tx: tx['address'] == 'yF4d7VrFUtr4h1rNEhwdNfrEQXbNvdCR8v', txs))[0]
                self.assertEqual('yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy', tx1['address'], 'expecting send tx1 address')
                self.assertEqual('yF4d7VrFUtr4h1rNEhwdNfrEQXbNvdCR8v', tx2['address'], 'expecting send tx2 address')
                self.assertEqual('send', tx1['category'], 'expecting send tx1')
                self.assertEqual('send', tx2['category'], 'expecting send tx2')
                self.assertEqual(-500, tx1['amount'], 'expecting send amount to equal')
                self.assertEqual(-90, tx1['fee'], 'expecting send fee to equal')
                self.assertEqual(-10, tx2['amount'], 'expecting send amount to equal')
                self.assertEqual(0, tx2['fee'], 'expecting send amount to equal')
            elif txid == 'befc41488710a2836832a481cf5cdb9e6fe31f8ef91ba691d177030e58ee1c30':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('receive', tx1['category'], 'expecting receive tx')
                self.assertEqual('yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm', tx1['address'], 'only expecting receive address')
                self.assertEqual(90, tx1['amount'], 'expecting receive amount to equal')
                self.assertEqual(0, tx1['fee'], 'expecting receive fee to equal')
            elif txid == '14bd21813a10e6a8db5f2f48fd40eb6b8be91e0013f2239f80360f2b1d688fbe':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('send', tx1['category'], 'only expecting send txs to foreign address')
                self.assertEqual('yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy', tx1['address'], 'only expecting send txs to foreign address')
                self.assertEqual(-5, tx1['amount'], 'expecting send amount to equal')
                self.assertEqual(-5, tx1['fee'], 'expecting send fee to equal')
            elif txid == '007c9e9a42cdba115eabbe557d45dcf09cb6fd61dfa7c8db40a4f25aa34a0d48':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('send', tx1['category'], 'only expecting send txs to foreign address')
                self.assertEqual('yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy', tx1['address'], 'only expecting send txs to foreign address')
                self.assertEqual(-5, tx1['amount'], 'expecting send amount to equal')
                self.assertEqual(-5, tx1['fee'], 'expecting send fee to equal')
            elif txid == 'a073fc4c52532632b98bd3d30c93970d3d0cf2cabcf85848aedeb2112cc3d0bd':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('send', tx1['category'], 'only expecting send txs to foreign address')
                self.assertEqual('yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy', tx1['address'], 'only expecting send txs to foreign address')
                self.assertEqual(-5, tx1['amount'], 'expecting send amount to equal')
                self.assertEqual(-5, tx1['fee'], 'expecting send fee to equal')
            elif txid == '07202b7da9b1847deda07f15c2c8c0be0400575a39a6fe1dde11bbac8c028dbc':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('send', tx1['category'], 'only expecting send txs to foreign address')
                self.assertEqual('yDg7Y4rLScMj2GKnDc4zXuVY34grMstKDy', tx1['address'], 'only expecting send txs to foreign address')
                self.assertEqual(-5, tx1['amount'], 'expecting send amount to equal')
                self.assertEqual(-5, tx1['fee'], 'expecting send fee to equal')

            actual_data_txs_ids.remove(txid)

        self.assertEqual(0, len(actual_data_txs_ids), 'expecting all data txids to be processed')

    @async_test
    async def test_get_history_amounts_2(self):
        tx_lookup2 = {
            'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a': make_tx(hash_t('txhash1'), [make_vin('0000000000000000000000000000000000000000000000000000000000000000', 0)], [make_vout(0.00027541, 0, ['1EzL7GZmrdgAYhBREAoiXiJqRdqk5i1MZM']), make_vout(0.00222209, 1, ['bc1qw4cl0hwhshrjz65eeupz3zcmwz8snq5m845rly'])], '000000000000000000030f209b4de0d798f6357b1fcc249b34be3d6a82dbc4f7'),
            '875e933ad470ef78f1ad0f9ed020f9787e22604b26d0cedd3d0c744446fd47de': make_tx(hash_t('txhash2'), [make_vin('0000000000000000000000000000000000000000000000000000000000000000', 0)], [make_vout(0.00105834, 0, ['1EzL7GZmrdgAYhBREAoiXiJqRdqk5i1MZM']), make_vout(0.00103933, 1, ['bc1q7dn7acwhj4djxg323wzm5f50906lhkfs5p2xdl'])], '0000000000000000000473080337c048be8408a16eab9e22cf162a3b41ddbb18'),
            '491eb677bc65aec4bfa01343971c6c1335e98083415f6484431e10085ce8f8bc': make_tx(hash_t('txhash3'), [make_vin('875e933ad470ef78f1ad0f9ed020f9787e22604b26d0cedd3d0c744446fd47de', 0), make_vin('f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a', 0)], [make_vout(0.001, 0, ['3QqoLrLtuNQSyj8W3NPvzonKy7psVWesNh']), make_vout(0.00017775, 1, ['1EzL7GZmrdgAYhBREAoiXiJqRdqk5i1MZM'])], '0000000000000000000cd4e766bc0a4162dc298af77fe4a2ae16ca2acc9a20f4'),
        }
        data = await get_history(['1EzL7GZmrdgAYhBREAoiXiJqRdqk5i1MZM'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup2), bump_cost, transaction_get(tx_lookup2), logger())
        actual_data_txs_ids = set(list(map(lambda tx: tx['txid'], data)))
        expecting_txs_ids = [
            'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a',
            '875e933ad470ef78f1ad0f9ed020f9787e22604b26d0cedd3d0c744446fd47de',
            '491eb677bc65aec4bfa01343971c6c1335e98083415f6484431e10085ce8f8bc',
        ]
        # Expecting all the txs in the data
        for txid in expecting_txs_ids:
            self.assertGreaterEqual(len(list(filter(lambda tx: tx['txid'] == txid, data))), 1)

            # Assert send/receive amounts
            txs = list(filter(lambda tx: tx['txid'] == txid, data))

            if txid == 'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('receive', tx1['category'], 'expecting to receive to address')
                self.assertEqual('1EzL7GZmrdgAYhBREAoiXiJqRdqk5i1MZM', tx1['address'], 'expecting to receive to address')
                self.assertEqual(0.00027541, tx1['amount'], 'expecting receive amount to equal')
                self.assertEqual(0, tx1['fee'], 'expecting receive fee to equal')
                actual_data_txs_ids.remove(txid)
            elif txid == '875e933ad470ef78f1ad0f9ed020f9787e22604b26d0cedd3d0c744446fd47de':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('receive', tx1['category'], 'expecting to receive to address')
                self.assertEqual('1EzL7GZmrdgAYhBREAoiXiJqRdqk5i1MZM', tx1['address'], 'expecting to receive to address')
                self.assertEqual(0.00105834, tx1['amount'], 'expecting receive amount to equal')
                self.assertEqual(0, tx1['fee'], 'expecting receive fee to equal')
                actual_data_txs_ids.remove(txid)
            elif txid == '491eb677bc65aec4bfa01343971c6c1335e98083415f6484431e10085ce8f8bc':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('send', tx1['category'], 'expecting send tx to foreign address')
                self.assertEqual('3QqoLrLtuNQSyj8W3NPvzonKy7psVWesNh', tx1['address'], 'expecting send tx to foreign address')
                self.assertEqual(-0.001, tx1['amount'], 'expecting send amount to equal')
                self.assertEqual(-0.000156, tx1['fee'], 'expecting send fee to equal')
                actual_data_txs_ids.remove(txid)


        self.assertEqual(0, len(actual_data_txs_ids), 'expecting all data txids to be processed')

    @async_test
    async def test_get_history_amounts_staking(self):
        tx_lookup2 = {
            'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a': make_tx(hash_t('txhash1'), [make_vin('0000000000000000000000000000000000000000000000000000000000000000', 0)], [make_vout(3061.56993931, 0, ['BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR'])], '4317511e5099d082484fe7dbdad15d402b52fd8c24250c4341977e40fb962d0d'),
            '875e933ad470ef78f1ad0f9ed020f9787e22604b26d0cedd3d0c744446fd47de': make_tx(hash_t('txhash2'), [make_vin('f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a', 0)], [make_vout(3062.56993931, 0, ['BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR'])], '011e68baada0bae217b1cbed897c30b96443c0a1bf0776be644cae3a565c9169'),
            '491eb677bc65aec4bfa01343971c6c1335e98083415f6484431e10085ce8f8bc': make_tx(hash_t('txhash3'), [make_vin('875e933ad470ef78f1ad0f9ed020f9787e22604b26d0cedd3d0c744446fd47de', 0)], [make_vout(3063.56993931, 0, ['BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR'])], '6132b80496c2941a479cba34f7130793978da8ae60cc62bc61527fbd38daaddf'),
            '9727c697a18404a1334dcb7d6d60cb2da43c021b96327a44e0d8e0e6291dcbe1': make_tx(hash_t('txhash4'), [make_vin('491eb677bc65aec4bfa01343971c6c1335e98083415f6484431e10085ce8f8bc', 0)], [make_vout(0.01500000000, 1, ['BmpyNqVPehhiuTCRbq9wSMCGcJz4WvAyBA']), make_vout(3063.55482171, 2, ['BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR'])], 'da12df50d7cf47e906118c3fdb73909b0b47a6cf65a7f569b698a00c03656521'),
        }
        data = await get_history(['BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup2), bump_cost, transaction_get(tx_lookup2), logger())
        actual_data_txs_ids = set(list(map(lambda tx: tx['txid'], data)))
        expecting_txs_ids = [
            'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a',
            '875e933ad470ef78f1ad0f9ed020f9787e22604b26d0cedd3d0c744446fd47de',
            '491eb677bc65aec4bfa01343971c6c1335e98083415f6484431e10085ce8f8bc',
            '9727c697a18404a1334dcb7d6d60cb2da43c021b96327a44e0d8e0e6291dcbe1',
        ]
        # Expecting all the txs in the data
        for txid in expecting_txs_ids:
            self.assertGreaterEqual(len(list(filter(lambda tx: tx['txid'] == txid, data))), 1)

            # Assert send/receive amounts
            txs = list(filter(lambda tx: tx['txid'] == txid, data))

            if txid == 'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('receive', tx1['category'], 'expecting to receive to address')
                self.assertEqual('BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR', tx1['address'], 'expecting to receive to address')
                self.assertEqual(3061.56993931, tx1['amount'], 'expecting receive amount to equal')
                self.assertEqual(0, tx1['fee'], 'expecting receive fee to equal')
                actual_data_txs_ids.remove(txid)
            elif txid == '875e933ad470ef78f1ad0f9ed020f9787e22604b26d0cedd3d0c744446fd47de':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('receive', tx1['category'], 'expecting to receive to address')
                self.assertEqual('BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR', tx1['address'], 'expecting to receive to address')
                self.assertEqual(1.0, tx1['amount'], 'expecting receive amount to equal')
                self.assertEqual(0, tx1['fee'], 'expecting receive fee to equal')
                actual_data_txs_ids.remove(txid)
            elif txid == '491eb677bc65aec4bfa01343971c6c1335e98083415f6484431e10085ce8f8bc':
                tx1 = txs[0]
                self.assertEqual('receive', tx1['category'], 'expecting to receive to address')
                self.assertEqual('BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR', tx1['address'], 'expecting to receive to address')
                self.assertEqual(1.0, tx1['amount'], 'expecting receive amount to equal')
                self.assertEqual(0, tx1['fee'], 'expecting receive fee to equal')
                actual_data_txs_ids.remove(txid)
            elif txid == '9727c697a18404a1334dcb7d6d60cb2da43c021b96327a44e0d8e0e6291dcbe1':
                self.assertEqual(1, len(txs), 'expecting transaction count')
                tx1 = txs[0]
                self.assertEqual('send', tx1['category'], 'expecting send tx to foreign address')
                self.assertEqual('BmpyNqVPehhiuTCRbq9wSMCGcJz4WvAyBA', tx1['address'], 'expecting send tx to foreign address')
                self.assertEqual(-0.015, tx1['amount'], 'expecting send amount to equal')
                self.assertEqual(-0.0001176, tx1['fee'], 'expecting send fee to equal')
                actual_data_txs_ids.remove(txid)


        self.assertEqual(0, len(actual_data_txs_ids), 'expecting all data txids to be processed')

    @async_test
    async def test_get_history_exception_bad_address(self):
        def make_vout_2(amount, n, addr_info):
            return {
                'n': n,
                'scriptPubKey': addr_info,
                'value': amount,
            }

        tx_lookup2 = {'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a': make_tx(hash_t('txhash1'), [make_vin('0', 0)], [make_vout_2(3061.56993931, 0, {'type': 'p2sh', 'addresses': 'BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR'})], '4317511e5099d082484fe7dbdad15d402b52fd8c24250c4341977e40fb962d0d')}
        data = await get_history(['BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup2), bump_cost, transaction_get(tx_lookup2), logger())
        self.assertEqual(1, len(data), 'expecting data for good address')

        tx_lookup2 = {'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a': make_tx(hash_t('txhash1'), [make_vin('0', 0)], [make_vout_2(3061.56993931, 0, {'type': 'p2sh', 'addresses': ['BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR']})], '4317511e5099d082484fe7dbdad15d402b52fd8c24250c4341977e40fb962d0d')}
        data = await get_history(['BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup2), bump_cost, transaction_get(tx_lookup2), logger())
        self.assertEqual(1, len(data), 'expecting data for good address list')

        tx_lookup2 = {'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a': make_tx(hash_t('txhash1'), [make_vin('0', 0)], [make_vout_2(3061.56993931, 0, {'type': 'nonstandard'})], '4317511e5099d082484fe7dbdad15d402b52fd8c24250c4341977e40fb962d0d')}
        data = await get_history(['BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup2), bump_cost, transaction_get(tx_lookup2), logger())
        self.assertEqual(0, len(data), 'expecting no data for nonstandard scriptpubkey')

        tx_lookup2 = {'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a': make_tx(hash_t('txhash1'), [make_vin('0', 0)], [make_vout_2(3061.56993931, 0, {'type': 'p2sh', 'addresses': ''})], '4317511e5099d082484fe7dbdad15d402b52fd8c24250c4341977e40fb962d0d')}
        data = await get_history(['BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup2), bump_cost, transaction_get(tx_lookup2), logger())
        self.assertEqual(0, len(data), 'expecting no data for empty address')

        tx_lookup2 = {'f6bb99f4b434dea6495fbe346c6271bd235804b7d41e585b471edfea147fe15a': make_tx(hash_t('txhash1'), [make_vin('0', 0)], [make_vout_2(3061.56993931, 0, {'type': 'p2sh', 'addresses': ['']})], '4317511e5099d082484fe7dbdad15d402b52fd8c24250c4341977e40fb962d0d')}
        data = await get_history(['BqeAD3u6T9yCvgbXizqPcYNBTSCq9RtWrR'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup2), bump_cost, transaction_get(tx_lookup2), logger())
        self.assertEqual(0, len(data), 'expecting no data for empty address list')

    @async_test
    async def test_get_history_json(self):
        err = None
        try:
            data = await get_history(['yDaL1ptNHk2EYrZ9BXeTdMRkGND9nBhLxm'], address_to_hashX, session_mgr(address_to_hashX, tx_lookup), bump_cost, transaction_get(tx_lookup), logger())
            json.dumps(data)
        except:
            err = True

        self.assertIsNone(err, 'expecting history to serialize into json')


if __name__ == '__main__':
    unittest.main()
