import codecs
import datetime
import sys
import time
import pylru
import electrumx
import electrumx.lib.util as util
from binascii import unhexlify, hexlify
from beaker.cache import CacheManager
from beaker.util import parse_cache_config_options
from aiorpcx import ReplyAndDisconnect, RPCError
from electrumx.lib.hash import sha256, hash_to_hex_str, hex_str_to_hash
from electrumx.server.daemon import DaemonError
from electrumx.server.session import SessionBase, assert_tx_hash, scripthash_to_hashX, non_negative_integer
from lbryschema.uri import parse_lbry_uri
from lbryschema.error import URIParseError

BAD_REQUEST = 1
DAEMON_ERROR = 2


def truncate(n, decimals=0):
    s = '{0:.{1}f}'.format(n, decimals)
    return float(s)


class ElectrumX(SessionBase):
    PROTOCOL_MIN = (1, 2)
    PROTOCOL_MAX = (1, 4, 1)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subscribe_headers = False
        self.subscribe_blocks = False
        self.connection.max_response_size = self.env.max_send
        self.hashX_subs = {}
        self.sv_seen = False
        self.mempool_statuses = {}
        self.set_request_handlers(self.PROTOCOL_MIN)
        self.is_peer = False
        self.cost = 5.0  # Connection cost
        self.cached_gettxoutsetinfo = None
        self.cached_rawblocks = None
        self.session_mgr._history_address_cache = pylru.lrucache(1000)

    @classmethod
    def protocol_min_max_strings(cls):
        return [util.version_string(ver)
                for ver in (cls.PROTOCOL_MIN, cls.PROTOCOL_MAX)]

    @classmethod
    def server_features(cls, env):
        '''Return the server features dictionary.'''
        hosts_dict = {}
        for service in env.report_services:
            port_dict = hosts_dict.setdefault(str(service.host), {})
            if service.protocol not in port_dict:
                port_dict[f'{service.protocol}_port'] = service.port

        min_str, max_str = cls.protocol_min_max_strings()
        return {
            'hosts': hosts_dict,
            'pruning': None,
            'server_version': electrumx.version,
            'protocol_min': min_str,
            'protocol_max': max_str,
            'genesis_hash': env.coin.GENESIS_HASH,
            'hash_function': 'sha256',
            'services': [str(service) for service in env.report_services],
        }

    async def server_features_async(self):
        self.bump_cost(0.2)
        return self.server_features(self.env)

    @classmethod
    def server_version_args(cls):
        '''The arguments to a server.version RPC call to a peer.'''
        return [electrumx.version, cls.protocol_min_max_strings()]

    def protocol_version_string(self):
        return util.version_string(self.protocol_tuple)

    def extra_cost(self):
        return self.session_mgr.extra_cost(self)

    def sub_count(self):
        return len(self.hashX_subs)

    def unsubscribe_hashX(self, hashX):
        self.mempool_statuses.pop(hashX, None)
        return self.hashX_subs.pop(hashX, None)

    async def notify(self, touched, height_changed):
        '''Notify the client about changes to touched addresses (from mempool
        updates or new blocks) and height.
        '''
        if height_changed and self.subscribe_headers:
            args = (await self.subscribe_headers_result(),)
            await self.send_notification('blockchain.headers.subscribe', args)

        if height_changed and self.subscribe_blocks:
            args = (await self.subscribe_blocks_result(),)
            await self.send_notification('blockchain.block.subscribe', args)

        touched = touched.intersection(self.hashX_subs)
        if touched or (height_changed and self.mempool_statuses):
            changed = {}

            for hashX in touched:
                alias = self.hashX_subs.get(hashX)
                if alias:
                    status = await self.subscription_address_status(hashX)
                    changed[alias] = status

            # Check mempool hashXs - the status is a function of the confirmed state of
            # other transactions.
            mempool_statuses = self.mempool_statuses.copy()
            for hashX, old_status in mempool_statuses.items():
                alias = self.hashX_subs.get(hashX)
                if alias:
                    status = await self.subscription_address_status(hashX)
                    if status != old_status:
                        changed[alias] = status

            method = 'blockchain.scripthash.subscribe'
            for alias, status in changed.items():
                await self.send_notification(method, (alias, status))

            if changed:
                es = '' if len(changed) == 1 else 'es'
                self.logger.info(f'notified of {len(changed):,d} address{es}')

    async def subscribe_headers_result(self):
        '''The result of a header subscription or notification.'''
        return self.session_mgr.hsub_results

    async def headers_subscribe(self):
        '''Subscribe to get raw headers of new blocks.'''
        self.subscribe_headers = True
        self.bump_cost(0.25)
        return await self.subscribe_headers_result()

    async def add_peer(self, features):
        '''Add a peer (but only if the peer resolves to the source).'''
        self.is_peer = True
        self.bump_cost(100.0)
        return await self.peer_mgr.on_add_peer(features, self.remote_address())

    async def peers_subscribe(self):
        '''Return the server peers as a list of (ip, host, details) tuples.'''
        self.bump_cost(1.0)
        return self.peer_mgr.on_peers_subscribe(self.is_tor())

    async def address_status(self, hashX):
        '''Returns an address status.
        Status is a hex string, but must be None if there is no history.
        '''
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if it has unconfirmed inputs, otherwise 0
        db_history, cost = await self.session_mgr.limited_history(hashX)
        mempool = await self.mempool.transaction_summaries(hashX)

        status = ''.join(f'{hash_to_hex_str(tx_hash)}:'
                         f'{height:d}:'
                         for tx_hash, height in db_history)
        status += ''.join(f'{hash_to_hex_str(tx.hash)}:'
                          f'{-tx.has_unconfirmed_inputs:d}:'
                          for tx in mempool)

        # Add status hashing cost
        self.bump_cost(cost + 0.1 + len(status) * 0.00002)

        if status:
            status = sha256(status.encode()).hex()
        else:
            status = None

        if mempool:
            self.mempool_statuses[hashX] = status
        else:
            self.mempool_statuses.pop(hashX, None)

        return status

    async def hashX_listunspent(self, hashX):
        '''Return the list of UTXOs of a script hash, including mempool
        effects.'''
        utxos = await self.db.all_utxos(hashX)
        utxos = sorted(utxos)
        utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        self.bump_cost(1.0 + len(utxos) / 50)
        spends = await self.mempool.potential_spends(hashX)

        return [{'tx_hash': hash_to_hex_str(utxo.tx_hash),
                 'tx_pos': utxo.tx_pos,
                 'height': utxo.height, 'value': utxo.value}
                for utxo in utxos
                if (utxo.tx_hash, utxo.tx_pos) not in spends]

    async def hashX_subscribe(self, hashX, alias):
        # Store the subscription only after address_status succeeds
        result = await self.address_status(hashX)
        self.hashX_subs[hashX] = alias
        return result

    async def address_get_balance(self, address):
        '''Return the confirmed and unconfirmed balance of an address.'''
        hashX = self.coin.address_to_hashX(address)
        return await self.get_balance(hashX)

    async def address_get_history(self, address):
        '''Return the confirmed and unconfirmed history of an address.'''
        hashX = self.coin.address_to_hashX(address)
        return await self.confirmed_and_unconfirmed_history(hashX)

    async def address_get_mempool(self, address):
        '''Return the mempool transactions touching an address.'''
        hashX = self.coin.address_to_hashX(address)
        return await self.unconfirmed_history(hashX)

    async def address_listunspent(self, address):
        '''Return the list of UTXOs of an address.'''
        hashX = self.coin.address_to_hashX(address)

        utxos = await self.db.all_utxos(hashX)
        utxos = sorted(utxos)
        utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        self.bump_cost(1.0 + len(utxos) / 50)
        spends = await self.mempool.potential_spends(hashX)

        return [{'address': address,
                 'tx_hash': hash_to_hex_str(utxo.tx_hash),
                 'tx_pos': utxo.tx_pos,
                 'height': utxo.height, 'value': utxo.value}
                for utxo in utxos
                if (utxo.tx_hash, utxo.tx_pos) not in spends]

    async def address_subscribe(self, address):
        '''Subscribe to an address.

        address: the address to subscribe to'''
        hashX = self.coin.address_to_hashX(address)
        return await self.hashX_subscribe(hashX, address)

    async def get_balance(self, hashX):
        utxos = await self.db.all_utxos(hashX)
        confirmed = sum(utxo.value for utxo in utxos)
        unconfirmed = await self.mempool.balance_delta(hashX)
        return {'confirmed': confirmed, 'unconfirmed': unconfirmed}

    async def scripthash_get_balance(self, scripthash):
        '''Return the confirmed and unconfirmed balance of a scripthash.'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.get_balance(hashX)

    async def unconfirmed_history(self, hashX):
        # Note unconfirmed history is unordered in electrum-server
        # height is -1 if it has unconfirmed inputs, otherwise 0
        result = [{'tx_hash': hash_to_hex_str(tx.hash),
                   'height': -tx.has_unconfirmed_inputs,
                   'fee': tx.fee}
                  for tx in await self.mempool.transaction_summaries(hashX)]
        self.bump_cost(0.25 + len(result) / 50)
        return result

    async def confirmed_and_unconfirmed_history(self, hashX):
        # Note history is ordered but unconfirmed is unordered in e-s
        history, cost = await self.session_mgr.limited_history(hashX)
        self.bump_cost(cost)
        conf = [{'tx_hash': hash_to_hex_str(tx_hash), 'height': height}
                for tx_hash, height in history]
        return conf + await self.unconfirmed_history(hashX)

    async def scripthash_get_history(self, scripthash):
        '''Return the confirmed and unconfirmed history of a scripthash.'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.confirmed_and_unconfirmed_history(hashX)

    async def scripthash_get_mempool(self, scripthash):
        '''Return the mempool transactions touching a scripthash.'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.unconfirmed_history(hashX)

    async def scripthash_listunspent(self, scripthash):
        '''Return the list of UTXOs of a scripthash.'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_listunspent(hashX)

    async def scripthash_subscribe(self, scripthash):
        '''Subscribe to a script hash.
        scripthash: the SHA256 hash of the script to subscribe to'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_subscribe(hashX, scripthash)

    async def scripthash_unsubscribe(self, scripthash):
        '''Unsubscribe from a script hash.'''
        self.bump_cost(0.1)
        hashX = scripthash_to_hashX(scripthash)
        return self.unsubscribe_hashX(hashX) is not None

    async def _merkle_proof(self, cp_height, height):
        max_height = self.db.db_height
        if not height <= cp_height <= max_height:
            raise RPCError(BAD_REQUEST,
                           f'require header height {height:,d} <= '
                           f'cp_height {cp_height:,d} <= '
                           f'chain height {max_height:,d}')
        branch, root = await self.db.header_branch_and_root(cp_height + 1,
                                                            height)
        return {
            'branch': [hash_to_hex_str(elt) for elt in branch],
            'root': hash_to_hex_str(root),
        }

    async def block_header(self, height, cp_height=0):
        '''Return a raw block header as a hexadecimal string, or as a
        dictionary with a merkle proof.'''
        height = non_negative_integer(height)
        cp_height = non_negative_integer(cp_height)
        raw_header_hex = (await self.session_mgr.raw_header(height)).hex()
        self.bump_cost(1.25 - (cp_height == 0))
        if cp_height == 0:
            return raw_header_hex
        result = {'header': raw_header_hex}
        result.update(await self._merkle_proof(cp_height, height))
        return result

    async def block_header_13(self, height):
        '''Return a raw block header as a hexadecimal string.

        height: the header's height'''
        return await self.block_header(height)

    async def block_headers(self, start_height, count, cp_height=0):
        '''Return count concatenated block headers as hex for the main chain;
        starting at start_height.
        start_height and count must be non-negative integers.  At most
        MAX_CHUNK_SIZE headers will be returned.
        '''
        start_height = non_negative_integer(start_height)
        count = non_negative_integer(count)
        cp_height = non_negative_integer(cp_height)
        cost = count / 50

        max_size = self.MAX_CHUNK_SIZE
        count = min(count, max_size)
        headers, count = await self.db.read_headers(start_height, count)
        result = {'hex': headers.hex(), 'count': count, 'max': max_size}
        if count and cp_height:
            cost += 1.0
            last_height = start_height + count - 1
            result.update(await self._merkle_proof(cp_height, last_height))
        self.bump_cost(cost)
        return result

    async def block_headers_12(self, start_height, count):
        return await self.block_headers(start_height, count)

    async def block_get_chunk(self, index):
        '''Return a chunk of block headers as a hexadecimal string.

        index: the chunk index'''
        index = non_negative_integer(index)
        size = self.coin.CHUNK_SIZE
        start_height = index * size
        headers, _ = await self.db.read_headers(start_height, size)
        return headers.hex()

    async def block_get_header(self, height):
        '''The deserialized header at a given height.

        height: the header's height'''
        height = non_negative_integer(height)
        return await self.session_mgr.electrum_header(height)

    def is_tor(self):
        '''Try to detect if the connection is to a tor hidden service we are
        running.'''
        proxy_address = self.peer_mgr.proxy_address()
        if not proxy_address:
            return False
        return self.remote_address().host == proxy_address.host

    async def replaced_banner(self, banner):
        network_info = await self.daemon_request('getnetworkinfo')
        ni_version = network_info['version']
        major, minor = divmod(ni_version, 1000000)
        minor, revision = divmod(minor, 10000)
        revision //= 100
        daemon_version = '{:d}.{:d}.{:d}'.format(major, minor, revision)
        for pair in [
            ('$SERVER_VERSION', electrumx.version_short),
            ('$SERVER_SUBVERSION', electrumx.version),
            ('$DAEMON_VERSION', daemon_version),
            ('$DAEMON_SUBVERSION', network_info['subversion']),
            ('$DONATION_ADDRESS', self.env.donation_address),
        ]:
            banner = banner.replace(*pair)
        return banner

    async def donation_address(self):
        '''Return the donation address as a string, empty if there is none.'''
        return self.env.donation_address

    async def banner(self):
        '''Return the server banner text.'''
        banner = f'You are connected to an {electrumx.version} server.'
        self.bump_cost(0.5)

        if self.is_tor():
            banner_file = self.env.tor_banner_file
        else:
            banner_file = self.env.banner_file
        if banner_file:
            try:
                with codecs.open(banner_file, 'r', 'utf-8') as f:
                    banner = f.read()
            except (OSError, UnicodeDecodeError) as e:
                self.logger.error(f'reading banner file {banner_file}: {e!r}')
            else:
                banner = await self.replaced_banner(banner)

        return banner

    async def relayfee(self):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        return await self.daemon_request('relayfee')

    async def estimatefee(self, number):
        '''The estimated transaction fee per kilobyte to be paid for a
        transaction to be included within a certain number of blocks.
        number: the number of blocks
        '''
        number = non_negative_integer(number)
        self.bump_cost(2.0)
        return await self.daemon_request('estimatefee', number)

    async def ping(self):
        '''Serves as a connection keep-alive mechanism and for the client to
        confirm the server is still responding.
        '''
        return None

    async def server_version(self, client_name='', protocol_version=None):
        '''Returns the server version as a string.
        client_name: a string identifying the client
        protocol_version: the protocol version spoken by the client
        '''
        self.bump_cost(0.5)
        if self.sv_seen:
            raise RPCError(BAD_REQUEST, f'server.version already sent')
        self.sv_seen = True

        if client_name:
            client_name = str(client_name)
            if self.env.drop_client is not None and \
                    self.env.drop_client.match(client_name):
                raise ReplyAndDisconnect(RPCError(
                    BAD_REQUEST, f'unsupported client: {client_name}'))
            self.client = client_name[:17]

        # Find the highest common protocol version.  Disconnect if
        # that protocol version in unsupported.
        ptuple, client_min = util.protocol_version(
            protocol_version, self.PROTOCOL_MIN, self.PROTOCOL_MAX)

        await self.crash_old_client(ptuple, self.env.coin.CRASH_CLIENT_VER)

        if ptuple is None:
            if client_min > self.PROTOCOL_MIN:
                self.logger.info(f'client requested future protocol version '
                                 f'{util.version_string(client_min)} '
                                 f'- is your software out of date?')
            raise ReplyAndDisconnect(RPCError(
                BAD_REQUEST, f'unsupported protocol version: {protocol_version}'))
        self.set_request_handlers(ptuple)

        return (electrumx.version, self.protocol_version_string())

    async def maybe_attempt_to_crash_old_client(self, proto_ver):
        return

    async def transaction_broadcast(self, raw_tx):
        '''Broadcast a raw transaction to the network.
        raw_tx: the raw transaction as a hexadecimal string'''
        self.bump_cost(0.25 + len(raw_tx) / 5000)
        # This returns errors as JSON RPC errors, as is natural
        try:
            hex_hash = await self.session_mgr.broadcast_transaction(raw_tx)
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.logger.info(f'error sending transaction: {message}')
            raise RPCError(BAD_REQUEST, 'the transaction was rejected by '
                                        f'network rules.\n\n{message}\n[{raw_tx}]')
        else:
            self.txs_sent += 1
            client_ver = util.protocol_tuple(self.client)
            if client_ver != (0,):
                msg = self.coin.warn_old_client_on_tx_broadcast(client_ver)
                if msg:
                    self.logger.info(f'sent tx: {hex_hash}. and warned user to upgrade their '
                                     f'client from {self.client}')
                    return msg

            self.logger.info(f'sent tx: {hex_hash}')
            return hex_hash

    async def transaction_get(self, tx_hash, verbose=False):
        '''Return the serialized raw transaction given its hash
        tx_hash: the transaction hash as a hexadecimal string
        verbose: passed on to the daemon
        '''
        assert_tx_hash(tx_hash)
        if verbose not in (True, False):
            raise RPCError(BAD_REQUEST, f'"verbose" must be a boolean')

        self.bump_cost(1.0)
        return await self.daemon_request('getrawtransaction', tx_hash, verbose)

    async def _block_hash_and_tx_hashes(self, height):
        '''Returns a pair (block_hash, tx_hashes) for the main chain block at
        the given height.

        block_hash is a hexadecimal string, and tx_hashes is an
        ordered list of hexadecimal strings.
        '''
        height = non_negative_integer(height)
        hex_hashes = await self.daemon_request('block_hex_hashes', height, 1)
        block_hash = hex_hashes[0]
        block = await self.daemon_request('deserialised_block', block_hash)
        return block_hash, block['tx']

    def _get_merkle_branch(self, tx_hashes, tx_pos):
        '''Return a merkle branch to a transaction.

        tx_hashes: ordered list of hex strings of tx hashes in a block
        tx_pos: index of transaction in tx_hashes to create branch for
        '''
        hashes = [hex_str_to_hash(hash) for hash in tx_hashes]
        branch, root = self.db.merkle.branch_and_root(hashes, tx_pos)
        branch = [hash_to_hex_str(hash) for hash in branch]
        return branch

    async def transaction_merkle(self, tx_hash, height):
        '''Return the merkle branch to a confirmed transaction given its hash
        and height.
        tx_hash: the transaction hash as a hexadecimal string
        height: the height of the block it is in
        '''
        tx_hash = assert_tx_hash(tx_hash)
        height = non_negative_integer(height)

        branch, tx_pos, cost = await self.session_mgr.merkle_branch_for_tx_hash(
            height, tx_hash)
        self.bump_cost(cost)

        return {"block_height": height, "merkle": branch, "pos": tx_pos}

    async def transaction_id_from_pos(self, height, tx_pos, merkle=False):
        '''Return the txid and optionally a merkle proof, given
        a block height and position in the block.
        '''
        tx_pos = non_negative_integer(tx_pos)
        height = non_negative_integer(height)
        if merkle not in (True, False):
            raise RPCError(BAD_REQUEST, f'"merkle" must be a boolean')

        if merkle:
            branch, tx_hash, cost = await self.session_mgr.merkle_branch_for_tx_pos(
                height, tx_pos)
            self.bump_cost(cost)
            return {"tx_hash": tx_hash, "merkle": branch}
        else:
            tx_hashes, cost = await self.session_mgr.tx_hashes_at_blockheight(height)
            try:
                tx_hash = tx_hashes[tx_pos]
            except IndexError:
                raise RPCError(BAD_REQUEST,
                               f'no tx at position {tx_pos:,d} in block at height {height:,d}')
            self.bump_cost(cost)
            return hash_to_hex_str(tx_hash)

    async def compact_fee_histogram(self):
        self.bump_cost(1.0)
        return await self.mempool.compact_fee_histogram()

    async def getrawmempool(self, verbose=False):
        if any(verbose == x for x in [1, '1', True, 'true', 'True']):
            verbose = True

        args = (verbose,)

        return await self.daemon_request('_send_single', 'getrawmempool', args)

    async def getblockcount(self):
        cached_height = self.session_mgr.daemon.cached_height()

        if cached_height is None:
            return await self.session_mgr.daemon.height()

        return cached_height

    async def getblock(self, hex_hash, verbose=False):
        if any(verbose == x for x in [1, '1', True, 'true', 'True']):
            verbose = True

        args = (hex_hash, verbose)

        return await self.daemon_request('_send_single', 'getblock', args)

    async def getblockhash(self, height):
        block_hash, tx_hashes = await self._block_hash_and_tx_hashes(height)

        return block_hash

    async def getblockchaininfo(self):
        return await self.daemon_request('_send_single', 'getblockchaininfo')

    async def gettxoutsetinfo(self):
        if self.cached_gettxoutsetinfo is None or (time.time() - self.cached_gettxoutsetinfo_update_time) > 600:
            self.cached_gettxoutsetinfo = await self.daemon_request('_send_single', 'gettxoutsetinfo')
            self.cached_gettxoutsetinfo_update_time = time.time()

        return self.cached_gettxoutsetinfo

    async def getmempoolinfo(self):
        return await self.daemon_request('_send_single', 'getmempoolinfo')

    async def get_db_raw_blocks(self, last_height, count):
        return await self.db.raw_blocks(last_height, count)

    async def cache_raw_blocks(self, count=110):
        if self.cached_rawblocks is None or (time.time() - self.cached_rawblocks_update_time) > 30:
            self.cached_rawblocks_update_time = time.time()
            height = await self.getblockcount()

            self.logger.info('Getting raw blocks for {}-{}'.format((height - count), height))

            self.cached_rawblocks = await self.get_db_raw_blocks(height, count)

        return self.cached_rawblocks

    async def getrawblocks(self, from_height, to_height):
        try:
            cached_blocks = await self.cache_raw_blocks()
            if (to_height - from_height) > len(cached_blocks):
                return []

            return sorted([(height, block) for height, block in cached_blocks if from_height <= height <= to_height],
                          key=lambda x: x[0], reverse=True)
        except Exception:
            return []

    async def block_subscribe(self):
        self.subscribe_blocks = True
        return await self.subscribe_blocks_result()

    async def subscribe_blocks_result(self):
        return self.session_mgr.bsub_results

    async def get_address_history(self, addresses):
        addr_lookup = set(addresses)
        spent = []
        spent_ids = set()
        processed_txs = set()  # track transactions that have already been processed
        for address in addr_lookup:
            address = str(address)

            try:
                hash_x = self.session_mgr._history_address_cache[address]
            except KeyError:
                hash_x = self.coin.address_to_hashX(address)
                self.session_mgr._history_address_cache[address] = hash_x
            except Exception:
                self.logger.exception('[GetAddressHistory] Exception while converting address')
                continue

            try:
                history = await self.db.limited_history(hash_x, limit=100)

                for tx_hash, height in history:
                    if tx_hash in processed_txs:
                        continue  # skip, already processed
                    tx = await self.transaction_get(hash_to_hex_str(tx_hash), verbose=True)
                    if not tx:
                        continue
                    processed_txs.add(tx_hash)

                    spends = []
                    from_addresses = set()
                    total_send_amount = 0
                    my_total_send_amount = 0
                    for item in tx['vin']:
                        prev_tx = await self.transaction_get(item['txid'], verbose=True)
                        if not prev_tx:
                            continue

                        prev_out_amount = prev_tx['vout'][item['vout']]['value']
                        addrs = prev_tx['vout'][item['vout']]['scriptPubKey']['addresses']
                        # record total sent coin if sent from one of our addresses
                        if len(addrs) > 0:
                            for addr in addrs:
                                if addr in addr_lookup:
                                    my_total_send_amount += prev_out_amount
                                    break

                        total_send_amount += prev_out_amount
                        from_addresses.update(addrs)

                    my_total_send_amount_running = my_total_send_amount  # track how much sent coin is left to report
                    is_sending_coin = my_total_send_amount > 0

                    biggest_sent_amount_not_my_address = 0
                    biggest_sent_address_not_my_address = ''
                    biggest_sent_amount_my_address = 0
                    biggest_sent_address_my_address = ''

                    fees = total_send_amount * -1

                    def valid_spend(p_spent_ids, p_address, p_amount, p_category, p_item, p_tx, p_from_addresses):
                        p_txid_n = (p_tx['txid'], p_item['n'], p_category)
                        if p_txid_n not in p_spent_ids:
                            return {
                                'address': p_address,
                                'amount': p_amount,
                                'fee': 0.0,
                                'vout': p_item['n'],
                                'category': p_category,
                                'confirmations': p_tx['confirmations'],
                                'blockhash': p_tx['blockhash'],
                                'blocktime': p_tx['blocktime'],
                                'time': p_tx['blocktime'],
                                'txid': p_tx['txid'],
                                'from_addresses': p_from_addresses
                            }, p_txid_n
                        else:
                            return None, None

                    def get_address(p_item):
                        if 'addresses' not in p_item['scriptPubKey'] or 'type' not in p_item['scriptPubKey'] \
                                or p_item['scriptPubKey']['type'] == 'nonstandard':
                            return None  # skip incompatible vout
                        if isinstance(p_item['scriptPubKey']['addresses'], str):
                            return p_item['scriptPubKey']['addresses']
                        elif isinstance(p_item['scriptPubKey']['addresses'], list):
                            return p_item['scriptPubKey']['addresses'][0]
                        else:
                            return None

                    # First pass: Only process transactions sent to another address, record fees
                    for item in tx['vout']:
                        # Add in fees (fees = total_in - total_out)
                        amount = item['value']
                        fees += amount
                        vout_address = get_address(item)
                        if not vout_address:
                            continue  # incompatible address, skip

                        if vout_address in addr_lookup:
                            continue  # not our address, skip

                        # Amount is negative for send and positive for receive
                        # Record sent coin to address if we have outstanding send amount.
                        # Note that my total sent amount is subtracted by any amounts
                        # previously marked sent.
                        # Compare with epsilon instead of 0 to avoid precision inaccuracies.
                        if my_total_send_amount_running > sys.float_info.epsilon:
                            if biggest_sent_amount_not_my_address < amount:
                                biggest_sent_amount_not_my_address = amount
                                biggest_sent_address_not_my_address = vout_address
                            # amount reported here cannot be larger than my total send amount
                            adjusted_amount = amount if my_total_send_amount_running > amount else my_total_send_amount_running
                            my_total_send_amount_running -= adjusted_amount  # track what we've already recorded as sent
                            spend, txid_n = valid_spend(spent_ids, vout_address, -float(adjusted_amount), 'send', item, tx,
                                                        list(from_addresses))
                            if spend:
                                spent_ids.add(txid_n)
                                spends.append(spend)

                    # Second pass: Only process transactions for all our own addresses
                    for item in tx['vout']:
                        vout_address = get_address(item)
                        if not vout_address:
                            continue  # incompatible address, skip
                        if vout_address not in addr_lookup:
                            continue  # skip, already processed in block above

                        amount = item['value']

                        do_not_mark_send = False
                        if vout_address not in from_addresses:
                            do_not_mark_send = True

                        # Record received coin if this vout address is mine
                        spend, txid_n = valid_spend(spent_ids, vout_address, float(amount), 'receive', item, tx,
                                                    list(from_addresses))
                        if spend:
                            spent_ids.add(txid_n)
                            spends.append(spend)

                        # Amount is negative for send and positive for receive
                        # Record sent coin to address if we have outstanding send amount.
                        # Note that my total sent amount is subtracted by any amounts
                        # previously marked sent.
                        # Compare with epsilon instead of 0 to avoid precision inaccuracies.
                        if my_total_send_amount_running > sys.float_info.epsilon:
                            # amount reported here cannot be larger than my total send amount
                            adjusted_amount = amount if my_total_send_amount_running > amount else my_total_send_amount_running
                            my_total_send_amount_running -= adjusted_amount  # track what we've already recorded as sent
                            if not do_not_mark_send:
                                spend, txid_n = valid_spend(spent_ids, vout_address, -float(adjusted_amount), 'send', item, tx,
                                                            list(from_addresses))
                                if spend:
                                    spent_ids.add(txid_n)
                                    spends.append(spend)

                                    if biggest_sent_amount_my_address < amount:
                                        biggest_sent_amount_my_address = amount
                                        biggest_sent_address_my_address = vout_address

                    # Assign fees on tx with largest sent amount. Assign fees to transactions
                    # sent to an address that is not our own. Otherwise assign fee to largest
                    # sent transaction on our own address if that applies.
                    if is_sending_coin and fees < 0:
                        for spend in spends:
                            biggest_sent_address = biggest_sent_address_not_my_address \
                                if biggest_sent_amount_not_my_address > 0 else biggest_sent_address_my_address
                            if spend['address'] == biggest_sent_address and spend['category'] == 'send':
                                spend['fee'] = truncate(fees, 10)
                                break

                    # Consolidate spends to self
                    remove_these = []
                    if len(spends) >= 2:  # can only compare at least 2 spends
                        for spend in spends:
                            filtered_spends = list(filter(lambda sp: sp['address'] == spend['address'], spends))
                            if not filtered_spends:
                                continue
                            sends = list(filter(lambda sp: sp['category'] == 'send', filtered_spends))
                            receives = list(filter(lambda sp: sp['category'] == 'receive', filtered_spends))
                            from_spend = None if len(sends) == 0 else sends[0]
                            from_receive = None if len(receives) == 0 else receives[0]
                            if not from_spend or not from_receive:
                                continue  # skip if don't have both send and receive
                            if abs(from_spend['amount']) - from_receive['amount'] > -sys.float_info.epsilon:
                                from_spend['amount'] += from_receive['amount']
                                from_spend['fee'] += from_receive['fee']
                                remove_these.append(from_receive)
                            elif abs(from_spend['amount']) - from_receive['amount'] <= -sys.float_info.epsilon:
                                from_receive['amount'] += from_spend['amount']
                                from_receive['fee'] += from_spend['fee']
                                remove_these.append(from_spend)
                            if len(spends) - len(remove_these) < 2:  # done processing if nothing left to compare
                                break
                    # Remove all the consolidated spends
                    if len(remove_these) > 0:
                        spends[:] = [spend for spend in spends if spend not in remove_these]

                    spent += spends
            except Exception:
                self.logger.exception('[GetAddressHistory] Exception while obtaining history')

        # self.logger.info(f'SPENT: {spent}')
        return spent

    async def get_history(self, addresses):
        self.logger.info('get_history: {}'.format(addresses))
        return await self.get_address_history(addresses)

    async def get_history_hashx(self, hashx_list):
        self.logger.info('get_history_hashx: {}'.format(hashx_list))
        addr_lookup = hashx_list
        spent = []
        spent_ids = set()
        processed_txs = set()  # track transactions that have already been processed
        for hash_x in addr_lookup:
            self.logger.info('get_history_hashx debug: {}'.format(hash_x))
            hash_x = hex_str_to_hash(hash_x)
            self.logger.info(hash_x)

            history = await self.db.limited_history(hash_x, limit=100)

            for tx_hash, height in history:
                if tx_hash in processed_txs:
                    continue  # skip, already processed
                tx = await self.transaction_get(hash_to_hex_str(tx_hash), verbose=True)
                if not tx:
                    continue
                processed_txs.add(tx_hash)

                spends = []
                from_addresses = set()
                total_send_amount = 0
                my_total_send_amount = 0
                for item in tx['vin']:
                    prev_tx = await self.transaction_get(item['txid'], verbose=True)
                    if not prev_tx:
                        continue

                    prev_out_amount = prev_tx['vout'][item['vout']]['value']
                    addrs = prev_tx['vout'][item['vout']]['scriptPubKey']['addresses']
                    # record total sent coin if sent from one of our addresses
                    if len(addrs) > 0:
                        for addr in addrs:
                            if addr in addr_lookup:
                                my_total_send_amount += prev_out_amount
                                break

                    total_send_amount += prev_out_amount
                    from_addresses.update(addrs)

                my_total_send_amount_running = my_total_send_amount  # track how much sent coin is left to report
                is_sending_coin = my_total_send_amount > 0

                biggest_sent_amount_not_my_address = 0
                biggest_sent_address_not_my_address = ''
                biggest_sent_amount_my_address = 0
                biggest_sent_address_my_address = ''

                fees = total_send_amount * -1

                def valid_spend(p_spent_ids, p_address, p_amount, p_category, p_item, p_tx, p_from_addresses):
                    p_txid_n = (p_tx['txid'], p_item['n'], p_category)
                    if p_txid_n not in p_spent_ids:
                        return {
                                   'address': p_address,
                                   'amount': p_amount,
                                   'fee': 0.0,
                                   'vout': p_item['n'],
                                   'category': p_category,
                                   'confirmations': p_tx['confirmations'],
                                   'blockhash': p_tx['blockhash'],
                                   'blocktime': p_tx['blocktime'],
                                   'time': p_tx['blocktime'],
                                   'txid': p_tx['txid'],
                                   'from_addresses': p_from_addresses
                               }, p_txid_n
                    else:
                        return None, None

                def get_address(p_item):
                    if 'addresses' not in p_item['scriptPubKey'] or 'type' not in p_item['scriptPubKey'] \
                            or p_item['scriptPubKey']['type'] == 'nonstandard':
                        return None  # skip incompatible vout
                    if isinstance(p_item['scriptPubKey']['addresses'], str):
                        return p_item['scriptPubKey']['addresses']
                    elif isinstance(p_item['scriptPubKey']['addresses'], list):
                        return p_item['scriptPubKey']['addresses'][0]
                    else:
                        return None

                # First pass: Only process transactions sent to another address, record fees
                for item in tx['vout']:
                    # Add in fees (fees = total_in - total_out)
                    amount = item['value']
                    fees += amount
                    vout_address = get_address(item)
                    if not vout_address:
                        continue  # incompatible address, skip

                    if vout_address in addr_lookup:
                        continue  # not our address, skip

                    # Amount is negative for send and positive for receive
                    # Record sent coin to address if we have outstanding send amount.
                    # Note that my total sent amount is subtracted by any amounts
                    # previously marked sent.
                    # Compare with epsilon instead of 0 to avoid precision inaccuracies.
                    if my_total_send_amount_running > sys.float_info.epsilon:
                        if biggest_sent_amount_not_my_address < amount:
                            biggest_sent_amount_not_my_address = amount
                            biggest_sent_address_not_my_address = vout_address
                        # amount reported here cannot be larger than my total send amount
                        adjusted_amount = amount if my_total_send_amount_running > amount else my_total_send_amount_running
                        my_total_send_amount_running -= adjusted_amount  # track what we've already recorded as sent
                        spend, txid_n = valid_spend(spent_ids, vout_address, -float(adjusted_amount), 'send', item,
                                                    tx,
                                                    list(from_addresses))
                        if spend:
                            spent_ids.add(txid_n)
                            spends.append(spend)

                # Second pass: Only process transactions for all our own addresses
                for item in tx['vout']:
                    vout_address = get_address(item)
                    if not vout_address:
                        continue  # incompatible address, skip
                    if vout_address not in addr_lookup:
                        continue  # skip, already processed in block above

                    amount = item['value']

                    do_not_mark_send = False
                    if vout_address not in from_addresses:
                        do_not_mark_send = True

                    # Record received coin if this vout address is mine
                    spend, txid_n = valid_spend(spent_ids, vout_address, float(amount), 'receive', item, tx,
                                                list(from_addresses))
                    if spend:
                        spent_ids.add(txid_n)
                        spends.append(spend)

                    # Amount is negative for send and positive for receive
                    # Record sent coin to address if we have outstanding send amount.
                    # Note that my total sent amount is subtracted by any amounts
                    # previously marked sent.
                    # Compare with epsilon instead of 0 to avoid precision inaccuracies.
                    if my_total_send_amount_running > sys.float_info.epsilon:
                        # amount reported here cannot be larger than my total send amount
                        adjusted_amount = amount if my_total_send_amount_running > amount else my_total_send_amount_running
                        my_total_send_amount_running -= adjusted_amount  # track what we've already recorded as sent
                        if not do_not_mark_send:
                            spend, txid_n = valid_spend(spent_ids, vout_address, -float(adjusted_amount), 'send',
                                                        item, tx,
                                                        list(from_addresses))
                            if spend:
                                spent_ids.add(txid_n)
                                spends.append(spend)

                                if biggest_sent_amount_my_address < amount:
                                    biggest_sent_amount_my_address = amount
                                    biggest_sent_address_my_address = vout_address

                # Assign fees on tx with largest sent amount. Assign fees to transactions
                # sent to an address that is not our own. Otherwise assign fee to largest
                # sent transaction on our own address if that applies.
                if is_sending_coin and fees < 0:
                    for spend in spends:
                        biggest_sent_address = biggest_sent_address_not_my_address \
                            if biggest_sent_amount_not_my_address > 0 else biggest_sent_address_my_address
                        if spend['address'] == biggest_sent_address and spend['category'] == 'send':
                            spend['fee'] = truncate(fees, 10)
                            break

                # Consolidate spends to self
                remove_these = []
                if len(spends) >= 2:  # can only compare at least 2 spends
                    for spend in spends:
                        filtered_spends = list(filter(lambda sp: sp['address'] == spend['address'], spends))
                        if not filtered_spends:
                            continue
                        sends = list(filter(lambda sp: sp['category'] == 'send', filtered_spends))
                        receives = list(filter(lambda sp: sp['category'] == 'receive', filtered_spends))
                        from_spend = None if len(sends) == 0 else sends[0]
                        from_receive = None if len(receives) == 0 else receives[0]
                        if not from_spend or not from_receive:
                            continue  # skip if don't have both send and receive
                        if abs(from_spend['amount']) - from_receive['amount'] > -sys.float_info.epsilon:
                            from_spend['amount'] += from_receive['amount']
                            from_spend['fee'] += from_receive['fee']
                            remove_these.append(from_receive)
                        elif abs(from_spend['amount']) - from_receive['amount'] <= -sys.float_info.epsilon:
                            from_receive['amount'] += from_spend['amount']
                            from_receive['fee'] += from_spend['fee']
                            remove_these.append(from_spend)
                        if len(spends) - len(remove_these) < 2:  # done processing if nothing left to compare
                            break
                # Remove all the consolidated spends
                if len(remove_these) > 0:
                    spends[:] = [spend for spend in spends if spend not in remove_these]

                spent += spends

        self.logger.info(f'SPENT: {spent}')
        return spent

    async def get_hashx(self, address):
        self.logger.info('get_hashx: {}'.format(address))
        hash_x = hash_to_hex_str(self.coin.address_to_hashX(address))
        self.logger.info('get_hashx result: {}'.format(hash_x))
        self.logger.info('get_hashx bytes result: {}'.format(self.coin.address_to_hashX(address)))

        return [hash_x]

    def set_request_handlers(self, ptuple):
        self.protocol_tuple = ptuple

        handlers = {
            'blockchain.address.get_balance': self.address_get_balance,
            'blockchain.address.get_history': self.address_get_history,
            'blockchain.address.get_mempool': self.address_get_mempool,
            'blockchain.address.listunspent': self.address_listunspent,
            'blockchain.address.subscribe': self.address_subscribe,
            'blockchain.block.header': self.block_header,
            'blockchain.block.headers': self.block_headers,
            'blockchain.block.get_chunk': self.block_get_chunk,
            'blockchain.block.get_header': self.block_get_header,
            'blockchain.estimatefee': self.estimatefee,
            'blockchain.relayfee': self.relayfee,
            'blockchain.headers.subscribe': self.headers_subscribe,
            'blockchain.scripthash.get_balance': self.scripthash_get_balance,
            'blockchain.scripthash.get_history': self.scripthash_get_history,
            'blockchain.scripthash.get_mempool': self.scripthash_get_mempool,
            'blockchain.scripthash.subscribe': self.scripthash_subscribe,
            'blockchain.transaction.broadcast': self.transaction_broadcast,
            'blockchain.transaction.get': self.transaction_get,
            'blockchain.transaction.get_merkle': self.transaction_merkle,
            'blockchain.transaction.id_from_pos': self.transaction_id_from_pos,
            'mempool.get_fee_histogram': self.mempool.compact_fee_histogram,
            'server.add_peer': self.add_peer,
            'server.banner': self.banner,
            'server.donation_address': self.donation_address,
            'server.features': self.server_features_async,
            'server.peers.subscribe': self.peers_subscribe,
            'server.ping': self.ping,
            'server.version': self.server_version,

            'getrawmempool': self.getrawmempool,
            'getblockcount': self.getblockcount,
            'getblock': self.getblock,
            'getblockhash': self.getblockhash,
            'blockchain.scripthash.listunspent': self.scripthash_listunspent,
            'getblockchaininfo': self.getblockchaininfo,
            'gettxoutsetinfo': self.gettxoutsetinfo,
            'getmempoolinfo': self.getmempoolinfo,
            'getrawblocks': self.getrawblocks,
            'blockchain.block.subscribe': self.block_subscribe,
            'gethistory': self.get_address_history,
            'gethashx': self.get_hashx,
            'gethistoryhashx': self.get_history_hashx,
        }

        self.request_handlers = handlers


class LocalRPC(SessionBase):
    '''A local TCP RPC server session.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = 'RPC'
        self.connection.max_response_size = 0

    def protocol_version_string(self):
        return 'RPC'


class DashElectrumX(ElectrumX):
    '''A TCP server that handles incoming Electrum Dash connections.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mns = set()
        self.mn_cache_height = 0
        self.mn_cache = []

    def set_request_handlers(self, ptuple):
        super().set_request_handlers(ptuple)
        self.request_handlers.update({
            'masternode.announce.broadcast':
                self.masternode_announce_broadcast,
            'masternode.subscribe': self.masternode_subscribe,
            'masternode.list': self.masternode_list,
            'protx.diff': self.protx_diff,
            'protx.info': self.protx_info,
        })

    async def notify(self, touched, height_changed):
        '''Notify the client about changes in masternode list.'''
        await super().notify(touched, height_changed)
        for mn in self.mns.copy():
            status = await self.daemon_request('masternode_list',
                                               ['status', mn])
            await self.send_notification('masternode.subscribe',
                                         [mn, status.get(mn)])

    # Masternode command handlers
    async def masternode_announce_broadcast(self, signmnb):
        '''Pass through the masternode announce message to be broadcast
        by the daemon.
        signmnb: signed masternode broadcast message.'''
        try:
            return await self.daemon_request('masternode_broadcast',
                                             ['relay', signmnb])
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.logger.info(f'masternode_broadcast: {message}')
            raise RPCError(BAD_REQUEST, 'the masternode broadcast was '
                                        f'rejected.\n\n{message}\n[{signmnb}]')

    async def masternode_subscribe(self, collateral):
        '''Returns the status of masternode.
        collateral: masternode collateral.
        '''
        result = await self.daemon_request('masternode_list',
                                           ['status', collateral])
        if result is not None:
            self.mns.add(collateral)
            return result.get(collateral)
        return None

    async def masternode_list(self, payees):
        '''
        Returns the list of masternodes.
        payees: a list of masternode payee addresses.
        '''
        if not isinstance(payees, list):
            raise RPCError(BAD_REQUEST, 'expected a list of payees')

        def get_masternode_payment_queue(mns):
            '''Returns the calculated position in the payment queue for all the
            valid masterernodes in the given mns list.
            mns: a list of masternodes information.
            '''
            now = int(datetime.datetime.utcnow().strftime("%s"))
            mn_queue = []

            # Only ENABLED masternodes are considered for the list.
            for line in mns:
                mnstat = mns[line].split()
                if mnstat[0] == 'ENABLED':
                    # if last paid time == 0
                    if int(mnstat[5]) == 0:
                        # use active seconds
                        mnstat.append(int(mnstat[4]))
                    else:
                        # now minus last paid
                        delta = now - int(mnstat[5])
                        # if > active seconds, use active seconds
                        if delta >= int(mnstat[4]):
                            mnstat.append(int(mnstat[4]))
                        # use active seconds
                        else:
                            mnstat.append(delta)
                    mn_queue.append(mnstat)
            mn_queue = sorted(mn_queue, key=lambda x: x[8], reverse=True)
            return mn_queue

        def get_payment_position(payment_queue, address):
            '''
            Returns the position of the payment list for the given address.
            payment_queue: position in the payment queue for the masternode.
            address: masternode payee address.
            '''
            position = -1
            for pos, mn in enumerate(payment_queue, start=1):
                if mn[2] == address:
                    position = pos
                    break
            return position

        # Accordingly with the masternode payment queue, a custom list
        # with the masternode information including the payment
        # position is returned.
        cache = self.session_mgr.mn_cache
        if not cache or self.session_mgr.mn_cache_height != self.db.db_height:
            full_mn_list = await self.daemon_request('masternode_list',
                                                     ['full'])
            mn_payment_queue = get_masternode_payment_queue(full_mn_list)
            mn_payment_count = len(mn_payment_queue)
            mn_list = []
            for key, value in full_mn_list.items():
                mn_data = value.split()
                mn_info = {}
                mn_info['vin'] = key
                mn_info['status'] = mn_data[0]
                mn_info['protocol'] = mn_data[1]
                mn_info['payee'] = mn_data[2]
                mn_info['lastseen'] = mn_data[3]
                mn_info['activeseconds'] = mn_data[4]
                mn_info['lastpaidtime'] = mn_data[5]
                mn_info['lastpaidblock'] = mn_data[6]
                mn_info['ip'] = mn_data[7]
                mn_info['paymentposition'] = get_payment_position(
                    mn_payment_queue, mn_info['payee'])
                mn_info['inselection'] = (
                        mn_info['paymentposition'] < mn_payment_count // 10)
                hashX = self.coin.address_to_hashX(mn_info['payee'])
                balance = await self.get_balance(hashX)
                mn_info['balance'] = (sum(balance.values())
                                      / self.coin.VALUE_PER_COIN)
                mn_list.append(mn_info)
            cache.clear()
            cache.extend(mn_list)
            self.session_mgr.mn_cache_height = self.db.db_height

        # If payees is an empty list the whole masternode list is returned
        if payees:
            return [mn for mn in cache if mn['payee'] in payees]
        else:
            return cache

    async def protx_diff(self, base_height, height):
        '''
        Calculates a diff between two deterministic masternode lists.
        The result also contains proof data.
        base_height: The starting block height (starting from 1).
        height: The ending block height.
        '''
        if not isinstance(base_height, int) or not isinstance(height, int):
            raise RPCError(BAD_REQUEST, 'expected a int block heights')

        max_height = self.db.db_height
        if (not 1 <= base_height <= max_height or
                not base_height <= height <= max_height):
            raise RPCError(BAD_REQUEST,
                           f'require 1 <= base_height {base_height:,d} <= '
                           f'height {height:,d} <= '
                           f'chain height {max_height:,d}')

        return await self.daemon_request('protx',
                                         ('diff', base_height, height))

    async def protx_info(self, protx_hash):
        '''
        Returns detailed information about a deterministic masternode.
        protx_hash: The hash of the initial ProRegTx
        '''
        if not isinstance(protx_hash, str):
            raise RPCError(BAD_REQUEST, 'expected protx hash string')

        res = await self.daemon_request('protx', ('info', protx_hash))
        if 'wallet' in res:
            del res['wallet']
        return res


class SmartCashElectrumX(DashElectrumX):
    '''A TCP server that handles incoming Electrum-SMART connections.'''

    def set_request_handlers(self, ptuple):
        super().set_request_handlers(ptuple)
        self.request_handlers.update({
            'smartrewards.current': self.smartrewards_current,
            'smartrewards.check': self.smartrewards_check
        })

    async def smartrewards_current(self):
        '''Returns the current smartrewards info.'''
        result = await self.daemon_request('smartrewards', ['current'])
        if result is not None:
            return result
        return None

    async def smartrewards_check(self, addr):
        '''
        Returns the status of an address

        addr: a single smartcash address
        '''
        result = await self.daemon_request('smartrewards', ['check', addr])
        if result is not None:
            return result
        return None


class AuxPoWElectrumX(ElectrumX):
    async def block_header(self, height, cp_height=0):
        result = await super().block_header(height, cp_height)

        # Older protocol versions don't truncate AuxPoW
        if self.protocol_tuple < (1, 4, 1):
            return result

        # Not covered by a checkpoint; return full AuxPoW data
        if cp_height == 0:
            return result

        # Covered by a checkpoint; truncate AuxPoW data
        result['header'] = self.truncate_auxpow(result['header'], height)
        return result

    async def block_headers(self, start_height, count, cp_height=0):
        result = await super().block_headers(start_height, count, cp_height)

        # Older protocol versions don't truncate AuxPoW
        if self.protocol_tuple < (1, 4, 1):
            return result

        # Not covered by a checkpoint; return full AuxPoW data
        if cp_height == 0:
            return result

        # Covered by a checkpoint; truncate AuxPoW data
        result['hex'] = self.truncate_auxpow(result['hex'], start_height)
        return result

    def truncate_auxpow(self, headers_full_hex, start_height):
        height = start_height
        headers_full = util.hex_to_bytes(headers_full_hex)
        cursor = 0
        headers = bytearray()

        while cursor < len(headers_full):
            headers.extend(headers_full[cursor:cursor + self.coin.TRUNCATED_HEADER_SIZE])
            cursor += self.db.dynamic_header_len(height)
            height += 1

        return headers.hex()


class BitcoinSegwitElectrumX(ElectrumX):

    async def maybe_attempt_to_crash_old_client(self, proto_ver):
        client_ver = util.protocol_tuple(self.client)
        is_old_protocol = proto_ver is None or proto_ver <= (1, 2)
        is_old_client = client_ver != (0,) and client_ver < (3, 2, 4)
        if is_old_protocol and is_old_client:
            self.logger.info(f'attempting to crash old client with version {self.client}')
            # this can crash electrum client 2.6 <= v < 3.1.2
            await self.send_notification('blockchain.relayfee', ())
            # this can crash electrum client (v < 2.8.2) UNION (3.0.0 <= v < 3.3.0)
            await self.send_notification('blockchain.estimatefee', ())


class SyscoinElectrumX(AuxPoWElectrumX):
    '''A TCP server that handles incoming Electrum Syscoin connections.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._mns = set()
        self.mn_cache_height = 0
        self.mn_cache = []

    def mns(self):
        if self._mns is None:
            self._mns = set()
        return self._mns

    def set_request_handlers(self, ptuple):
        super().set_request_handlers(ptuple)
        self.request_handlers.update({
            'masternode.announce.broadcast': self.masternode_announce_broadcast,
            'masternode.subscribe': self.masternode_subscribe,
            'masternode.list': self.masternode_list,
        })

    async def notify(self, touched, height_changed):
        '''Notify the client about changes in masternode list.'''
        await super().notify(touched, height_changed)
        for mn in self.mns().copy():
            status = await self.daemon_request('masternode_list', ['status', mn])
            await self.send_notification('masternode.subscribe', [mn, status.get(mn)])

    # Masternode command handlers
    async def masternode_announce_broadcast(self, signmnb):
        '''Pass through the masternode announce message to be broadcast
        by the daemon.
        signmnb: signed masternode broadcast message.'''
        try:
            return await self.daemon_request('masternode_broadcast', ['relay', signmnb])
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.logger.info(f'masternode_broadcast: {message}')
            raise RPCError(BAD_REQUEST, 'the masternode broadcast was rejected.\n\n{message}\n[{signmnb}]')

    async def masternode_subscribe(self, collateral):
        '''Returns the status of masternode.
        collateral: masternode collateral.
        '''
        result = await self.daemon_request('masternode_list', ['status', collateral])
        if result is not None:
            self.mns().add(collateral)
            return result.get(collateral)
        return None

    async def masternode_list(self, payees):
        '''
        Returns the list of masternodes.
        payees: a list of masternode payee addresses.
        '''
        if not isinstance(payees, list):
            raise RPCError(BAD_REQUEST, 'expected a list of payees')

        def get_masternode_payment_queue(mns):
            '''Returns the calculated position in the payment queue for all the
            valid masterernodes in the given mns list.
            mns: a list of masternodes information.
            '''
            now = int(datetime.datetime.utcnow().strftime("%s"))
            mn_queue = []

            # Only ENABLED masternodes are considered for the list.
            for line in mns:
                mnstat = mns[line].split()
                if mnstat[0] == 'ENABLED':
                    # if last paid time == 0
                    if int(mnstat[5]) == 0:
                        # use active seconds
                        mnstat.append(int(mnstat[4]))
                    else:
                        # now minus last paid
                        delta = now - int(mnstat[5])
                        # if > active seconds, use active seconds
                        if delta >= int(mnstat[4]):
                            mnstat.append(int(mnstat[4]))
                        # use active seconds
                        else:
                            mnstat.append(delta)
                    mn_queue.append(mnstat)
            mn_queue = sorted(mn_queue, key=lambda x: x[8], reverse=True)
            return mn_queue

        def get_payment_position(payment_queue, address):
            '''
            Returns the position of the payment list for the given address.
            payment_queue: position in the payment queue for the masternode.
            address: masternode payee address.
            '''
            position = -1
            for pos, mn in enumerate(payment_queue, start=1):
                if mn[2] == address:
                    position = pos
                    break
            return position

        # Accordingly with the masternode payment queue, a custom list
        # with the masternode information including the payment
        # position is returned.
        cache = self.session_mgr.mn_cache
        if not cache or self.session_mgr.mn_cache_height != self.db.db_height:
            full_mn_list = await self.daemon_request('masternode_list', ['full'])
            mn_payment_queue = get_masternode_payment_queue(full_mn_list)
            mn_payment_count = len(mn_payment_queue)
            mn_list = []
            for key, value in full_mn_list.items():
                mn_data = value.split()
                mn_info = {}
                mn_info['vin'] = key
                mn_info['status'] = mn_data[0]
                mn_info['protocol'] = mn_data[1]
                mn_info['payee'] = mn_data[2]
                mn_info['lastseen'] = mn_data[3]
                mn_info['activeseconds'] = mn_data[4]
                mn_info['lastpaidtime'] = mn_data[5]
                mn_info['lastpaidblock'] = mn_data[6]
                mn_info['ip'] = mn_data[7]
                mn_info['paymentposition'] = get_payment_position(mn_payment_queue, mn_info['payee'])
                mn_info['inselection'] = (mn_info['paymentposition'] < mn_payment_count // 10)
                hashX = self.coin.address_to_hashX(mn_info['payee'])
                balance = await self.get_balance(hashX)
                mn_info['balance'] = (sum(balance.values()) / self.coin.VALUE_PER_COIN)
                mn_list.append(mn_info)
            cache.clear()
            cache.extend(mn_list)
            self.session_mgr.mn_cache_height = self.db.db_height

        # If payees is an empty list the whole masternode list is returned
        if payees:
            return [mn for mn in cache if mn['payee'] in payees]
        else:
            return cache


def setup_caching(data_dir):
    cache_opts = {
        'cache.type': 'dbm',
        'cache.data_dir': data_dir,
        'cache.lock_dir': data_dir,
        'cache.regions': 'short_term, long_term',
        'cache.short_term.type': 'dbm',
    }

    cache_manager = CacheManager(**parse_cache_config_options(cache_opts))
    short_term_cache = cache_manager.get_cache('short_term', expire=240)
    return short_term_cache


class LBRYElectrumX(ElectrumX):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache = setup_caching(self.env.db_dir)

    def set_protocol_handlers(self, ptuple):
        super().set_protocol_handlers(ptuple)
        handlers = {
            'blockchain.transaction.get_height': self.transaction_get_height,
            'blockchain.claimtrie.getclaimbyid': self.claimtrie_getclaimbyid,
            'blockchain.claimtrie.getclaimsforname': self.claimtrie_getclaimsforname,
            'blockchain.claimtrie.getclaimsbyids': self.claimtrie_getclaimsbyids,
            'blockchain.claimtrie.getvalue': self.claimtrie_getvalue,
            'blockchain.claimtrie.getnthclaimforname': self.claimtrie_getnthclaimforname,
            'blockchain.claimtrie.getclaimsintx': self.claimtrie_getclaimsintx,
            'blockchain.claimtrie.getclaimssignedby': self.claimtrie_getclaimssignedby,
            'blockchain.claimtrie.getclaimssignedbynthtoname': self.claimtrie_getclaimssignedbynthtoname,
            'blockchain.claimtrie.getvalueforuri': self.claimtrie_getvalueforuri,
            'blockchain.claimtrie.getvaluesforuris': self.claimtrie_getvalueforuris,
            'blockchain.claimtrie.getclaimssignedbyid': self.claimtrie_getclaimssignedbyid,
            'blockchain.block.get_server_height': self.get_server_height,
            'blockchain.block.get_block': self.get_block,
        }
        self.electrumx_handlers.update(handlers)

    async def get_block(self, block_hash):
        return await self.daemon.deserialised_block(block_hash)

    def get_server_height(self):
        return self.bp.height

    async def transaction_get_height(self, tx_hash):
        self.assert_tx_hash(tx_hash)
        transaction_info = await self.daemon.getrawtransaction(tx_hash, True)
        if transaction_info and 'hex' in transaction_info and 'confirmations' in transaction_info:
            # an unconfirmed transaction from lbrycrdd will not have a 'confirmations' field
            height = self.bp.db_height
            height = height - transaction_info['confirmations']
            return height
        elif transaction_info and 'hex' in transaction_info:
            return -1
        return None

    async def claimtrie_getclaimssignedby(self, name):
        winning_claim = await self.daemon.getvalueforname(name)
        if winning_claim:
            return await self.claimtrie_getclaimssignedbyid(winning_claim['claimId'])

    async def claimtrie_getclaimssignedbyid(self, certificate_id):
        claim_ids = self.get_claim_ids_signed_by(certificate_id)
        return await self.batched_formatted_claims_from_daemon(claim_ids)

    def get_claim_ids_signed_by(self, certificate_id):
        raw_certificate_id = unhexlify(certificate_id)[::-1]
        raw_claim_ids = self.bp.get_signed_claim_ids_by_cert_id(raw_certificate_id)
        return list(map(hash_to_hex_str, raw_claim_ids))

    def get_signed_claims_with_name_for_channel(self, channel_id, name):
        claim_ids_for_name = list(self.bp.get_claims_for_name(name.encode('ISO-8859-1')).keys())
        claim_ids_for_name = set(map(hash_to_hex_str, claim_ids_for_name))
        channel_claim_ids = set(self.get_claim_ids_signed_by(channel_id))
        return claim_ids_for_name.intersection(channel_claim_ids)

    async def claimtrie_getclaimssignedbynthtoname(self, name, n):
        n = int(n)
        for claim_id, sequence in self.bp.get_claims_for_name(name.encode('ISO-8859-1')).items():
            if n == sequence:
                return await self.claimtrie_getclaimssignedbyid(hash_to_hex_str(claim_id))

    async def claimtrie_getclaimsintx(self, txid):
        # TODO: this needs further discussion.
        # Code on lbryum-server is wrong and we need to gather what we clearly expect from this command
        claim_ids = [claim['claimId'] for claim in (await self.daemon.getclaimsfortx(txid)) if 'claimId' in claim]
        return await self.batched_formatted_claims_from_daemon(claim_ids)

    async def claimtrie_getvalue(self, name, block_hash=None):
        proof = await self.daemon.getnameproof(name, block_hash)
        result = {'proof': proof, 'supports': []}

        if proof_has_winning_claim(proof):
            tx_hash, nout = proof['txhash'], int(proof['nOut'])
            transaction_info = await self.daemon.getrawtransaction(tx_hash, True)
            result['transaction'] = transaction_info['hex']
            result['height'] = (self.bp.db_height - transaction_info['confirmations']) + 1
            raw_claim_id = self.bp.get_claim_id_from_outpoint(unhexlify(tx_hash)[::-1], nout)
            sequence = self.bp.get_claims_for_name(name.encode('ISO-8859-1')).get(raw_claim_id)
            if sequence:
                claim_id = hexlify(raw_claim_id[::-1]).decode()
                claim_info = await self.daemon.getclaimbyid(claim_id)
                if not claim_info or not claim_info.get('value'):
                    claim_info = await self.slow_get_claim_by_id_using_name(claim_id)
                result['claim_sequence'] = sequence
                result['claim_id'] = claim_id
                supports = self.format_supports_from_daemon(claim_info.get('supports', []))  # fixme: lbrycrd#124
                result['supports'] = supports
            else:
                self.log_warning('tx has no claims in db: {} {}'.format(tx_hash, nout))
        return result

    async def claimtrie_getnthclaimforname(self, name, n):
        n = int(n)
        for claim_id, sequence in self.bp.get_claims_for_name(name.encode('ISO-8859-1')).items():
            if n == sequence:
                return await self.claimtrie_getclaimbyid(hash_to_hex_str(claim_id))

    async def claimtrie_getclaimsforname(self, name):
        claims = await self.daemon.getclaimsforname(name)
        if claims:
            claims['claims'] = [self.format_claim_from_daemon(claim, name) for claim in claims['claims']]
            claims['supports_without_claims'] = claims['supports without claims']
            del claims['supports without claims']
            claims['last_takeover_height'] = claims['nLastTakeoverHeight']
            del claims['nLastTakeoverHeight']
            return claims
        return {}

    async def batched_formatted_claims_from_daemon(self, claim_ids):
        claims = await self.daemon.getclaimsbyids(claim_ids)
        result = []
        for claim, claim_id in zip(claims, claim_ids):
            if claim and claim.get('value'):
                result.append(self.format_claim_from_daemon(claim))
            else:
                recovered_claim = await self.slow_get_claim_by_id_using_name(claim_id)
                result.append(self.format_claim_from_daemon(recovered_claim))
        return result

    def format_claim_from_daemon(self, claim, name=None):
        '''Changes the returned claim data to the format expected by lbrynet and adds missing fields.'''
        if not claim: return {}
        name = name or claim['name']
        claim_id = claim['claimId']
        raw_claim_id = unhexlify(claim_id)[::-1]
        if not self.bp.get_claim_info(raw_claim_id):
            #raise RPCError("Lbrycrd has {} but not lbryumx, please submit a bug report.".format(claim_id))
            return {}
        address = self.bp.get_claim_info(raw_claim_id).address.decode()
        sequence = self.bp.get_claims_for_name(name.encode('ISO-8859-1')).get(raw_claim_id)
        if not sequence:
            return {}
        supports = self.format_supports_from_daemon(claim.get('supports', []))  # fixme: lbrycrd#124

        amount = get_from_possible_keys(claim, 'amount', 'nAmount')
        height = get_from_possible_keys(claim, 'height', 'nHeight')
        effective_amount = get_from_possible_keys(claim, 'effective amount', 'nEffectiveAmount')
        valid_at_height = get_from_possible_keys(claim, 'valid at height', 'nValidAtHeight')

        return {
            "name": name,
            "claim_id": claim['claimId'],
            "txid": claim['txid'],
            "nout": claim['n'],
            "amount": amount,
            "depth": self.bp.db_height - height,
            "height": height,
            "value": hexlify(claim['value'].encode('ISO-8859-1')).decode(),
            "claim_sequence": sequence,  # from index
            "address": address,  # from index
            "supports": supports, # fixme: to be included in lbrycrd#124
            "effective_amount": effective_amount,
            "valid_at_height": valid_at_height  # TODO PR lbrycrd to include it
        }

    def format_supports_from_daemon(self, supports):
        return [[support['txid'], support['n'], get_from_possible_keys(support, 'amount', 'nAmount')] for
                 support in supports]

    async def claimtrie_getclaimbyid(self, claim_id):
        self.assert_claim_id(claim_id)
        claim = await self.daemon.getclaimbyid(claim_id)
        if not claim or not claim.get('value'):
            claim = await self.slow_get_claim_by_id_using_name(claim_id)
        return self.format_claim_from_daemon(claim)

    async def claimtrie_getclaimsbyids(self, *claim_ids):
        claims = await self.batched_formatted_claims_from_daemon(claim_ids)
        return dict(zip(claim_ids, claims))

    def assert_tx_hash(self, value):
        '''Raise an RPCError if the value is not a valid transaction
        hash.'''
        try:
            if len(util.hex_to_bytes(value)) == 32:
                return
        except Exception:
            pass
        raise RPCError('{} should be a transaction hash'.format(value))

    def assert_claim_id(self, value):
        '''Raise an RPCError if the value is not a valid claim id
        hash.'''
        try:
            if len(util.hex_to_bytes(value)) == 20:
                return
        except Exception:
            pass
        raise RPCError('{} should be a claim id hash'.format(value))

    async def slow_get_claim_by_id_using_name(self, claim_id):
        # TODO: temporary workaround for a lbrycrd bug on indexing. Should be removed when it gets stable
        raw_claim_id = unhexlify(claim_id)[::-1]
        claim = self.bp.get_claim_info(raw_claim_id)
        if claim:
            name = claim.name.decode('ISO-8859-1')
            claims = await self.daemon.getclaimsforname(name)
            for claim in claims['claims']:
                if claim['claimId'] == claim_id:
                    claim['name'] = name
                    self.log_warning('Recovered a claim missing from lbrycrd index: {} {}'.format(name, claim_id))
                    return claim

    async def claimtrie_getvalueforuri(self, block_hash, uri):
        key = str((block_hash, uri))
        if key in self.cache:
            return self.cache[key]
        # TODO: this thing is huge, refactor
        CLAIM_ID = "claim_id"
        WINNING = "winning"
        SEQUENCE = "sequence"
        uri = uri
        block_hash = block_hash
        try:
            parsed_uri = parse_lbry_uri(uri)
        except URIParseError as err:
            return {'error': err.message}
        result = {}

        if parsed_uri.is_channel:
            certificate = None

            # TODO: this is also done on the else, refactor
            if parsed_uri.claim_id:
                certificate_info = await self.claimtrie_getclaimbyid(parsed_uri.claim_id)
                if certificate_info and certificate_info['name'] == parsed_uri.name:
                    certificate = {'resolution_type': CLAIM_ID, 'result': certificate_info}
            elif parsed_uri.claim_sequence:
                certificate_info = await self.claimtrie_getnthclaimforname(parsed_uri.name, parsed_uri.claim_sequence)
                if certificate_info:
                    certificate = {'resolution_type': SEQUENCE, 'result': certificate_info}
            else:
                certificate_info = await self.claimtrie_getvalue(parsed_uri.name, block_hash)
                if certificate_info:
                    certificate = {'resolution_type': WINNING, 'result': certificate_info}

            if certificate and 'claim_id' not in certificate['result']:
                return result

            if certificate and not parsed_uri.path:
                result['certificate'] = certificate
                channel_id = certificate['result']['claim_id']
                claims_in_channel = await self.claimtrie_getclaimssignedbyid(channel_id)
                result['unverified_claims_in_channel'] = {claim['claim_id']: (claim['name'], claim['height'])
                                                          for claim in claims_in_channel if claim}
            elif certificate:
                result['certificate'] = certificate
                channel_id = certificate['result']['claim_id']
                claim_ids_matching_name = self.get_signed_claims_with_name_for_channel(channel_id, parsed_uri.path)
                claims = await self.batched_formatted_claims_from_daemon(claim_ids_matching_name)

                claims_in_channel = {claim['claim_id']: (claim['name'], claim['height'])
                                     for claim in claims}
                result['unverified_claims_for_name'] = claims_in_channel
        else:
            claim = None
            if parsed_uri.claim_id:
                claim_info = await self.claimtrie_getclaimbyid(parsed_uri.claim_id)
                if claim_info and claim_info['name'] == parsed_uri.name:
                    claim = {'resolution_type': CLAIM_ID, 'result': claim_info}
            elif parsed_uri.claim_sequence:
                claim_info = await self.claimtrie_getnthclaimforname(parsed_uri.name, parsed_uri.claim_sequence)
                if claim_info:
                    claim = {'resolution_type': SEQUENCE, 'result': claim_info}
            else:
                claim_info = await self.claimtrie_getvalue(parsed_uri.name, block_hash)
                if claim_info:
                    claim = {'resolution_type': WINNING, 'result': claim_info}
            if (claim and
                    # is not an unclaimed winning name
                    (claim['resolution_type'] != WINNING or proof_has_winning_claim(claim['result']['proof']))):
                raw_claim_id = unhexlify(claim['result']['claim_id'])[::-1]
                raw_certificate_id = self.bp.get_claim_info(raw_claim_id).cert_id
                if raw_certificate_id:
                    certificate_id = hash_to_hex_str(raw_certificate_id)
                    certificate = await self.claimtrie_getclaimbyid(certificate_id)
                    if certificate:
                        certificate = {'resolution_type': CLAIM_ID,
                                       'result': certificate}
                        result['certificate'] = certificate
                result['claim'] = claim
        self.cache[key] = result
        return result

    async def claimtrie_getvalueforuris(self, block_hash, *uris):
        MAX_BATCH_URIS = 500
        if len(uris) > MAX_BATCH_URIS:
            raise Exception("Exceeds max batch uris of {}".format(MAX_BATCH_URIS))

        return {uri: await self.claimtrie_getvalueforuri(block_hash, uri) for uri in uris}

        # TODO: get it all concurrently when lbrycrd pending changes goes into a stable release
        #async def getvalue(uri):
        #    value = await self.claimtrie_getvalueforuri(block_hash, uri)
        #    return uri, value,
        #return dict([await asyncio.gather(*tuple(getvalue(uri) for uri in uris))][0])


def proof_has_winning_claim(proof):
    return {'txhash', 'nOut'}.issubset(proof.keys())


def get_from_possible_keys(dictionary, *keys):
    for key in keys:
        if key in dictionary:
            return dictionary[key]
