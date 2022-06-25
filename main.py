#!/usr/bin/env python3

import asyncio
import sys
import logging
import traceback
from os import environ, getcwd, mkdir, remove
from os.path import isdir, exists
from electrumx import Env
from electrumx.lib.util import CompactFormatter, make_logger
from kubernetes.config import ConfigException
from server.db import Database
from server.controller import Controller
from server.utxoplugin_coins import (Coin, Blocknet, BlocknetTestnet,
                                     BitcoinSegwit, Bitcore, Litecoin, Dash, DigiByte,
                                     Syscoin, Phore, Alqo, Bitbay, Dogecoin, Ravencoin,
                                     Polis, Pivx, Trezarcoin, BitcoinCash, Stakenet, LBC)

coin_map = {
    "BLOCK": Blocknet,
    "TBLOCK": BlocknetTestnet,
    "BTC": BitcoinSegwit,
    "BCH": BitcoinCash,
    "BTX": Bitcore,
    "SYS": Syscoin,
    "LTC": Litecoin,
    "DASH": Dash,
    "DGB": DigiByte,
    "DOGE": Dogecoin,
    "POLIS": Polis,
    "PHR": Phore,
    "XLQ": Alqo,
    "BAY": Bitbay,
    "RVN": Ravencoin,
    "PIVX": Pivx,
    "TZC": Trezarcoin,
    "XSN": Stakenet,
    "LBRY": LBC,
}

coin = environ.get('PLUGIN_COIN')
db_dir = "{}/utxoplugin-{}".format(getcwd(), coin)

port = environ.get('PLUGIN_PORT', 8000)

environ['DB_ENGINE'] = environ.get('DB_ENGINE') or 'rocksdb'
environ['CACHE_MB'] = '2000'
environ['COST_SOFT_LIMIT'] = '0'
environ['COST_HARD_LIMIT'] = '0'
environ['INITIAL_CONCURRENT'] = '1000'
environ['EVENT_LOOP_POLICY'] = 'uvloop'
environ['PEER_ANNOUNCE'] = ''
environ['SERVICES'] = 'tcp://:{},rpc://:{},ws://:50000'.format(int(port) + 1000, port)


async def compact_history(env):
    if sys.version_info < (3, 7):
        raise RuntimeError('Python >= 3.7 is required to run ElectrumX')

    environ['DAEMON_URL'] = ''  # Avoid Env erroring out
    db = Database(env)
    await db.open_for_compacting()

    if db.first_sync or db.first_sync is None:
        return

    history = db.history
    # Continue where we left off, if interrupted
    if history.comp_cursor == -1:
        history.comp_cursor = 0

    history.comp_flush_count = max(history.comp_flush_count, 1)
    limit = 8 * 1000 * 1000

    while history.comp_cursor != -1:
        history._compact_history(limit)

    # When completed also update the UTXO flush count
    db.set_flush_count(history.flush_count)

    del db

    delete_lock_files()


def delete_lock_files():
    try:
        remove("utxo/LOCK")
    except Exception as e:
        print(e)

    try:
        remove("hist/LOCK")
    except Exception as e:
        print(e)


def main(db_compacted=False):
    network = environ.get('NETWORK')
    skip_compacting = environ.get('SKIP_COMPACT', 'false')
    
    print('[utxoplugin] Data-Directory: {}'.format(db_dir))

    delete_lock_files()

    coin_host_addr = environ.get('HOST_ADDRESS')
    rpc_port = environ.get('HOST_RPC_PORT')
    rpc_user = environ.get('RPC_USER')
    rpc_pass = environ.get('RPC_PASSWORD')

    if coin_host_addr is None or rpc_port is None:
        print("[utxoplugin] ERROR: Couldn't find coin host or rpc port!")

    url = "http://{}:{}@{}:{}".format(rpc_user, rpc_pass, coin_host_addr, rpc_port)

    if coin in coin_map.keys():
        MappedCoin = coin_map[coin]
    else:
        if network is None:
            network = 'mainnet'

        MappedCoin = Coin.lookup_coin_class(coin, network)

    environ['DAEMON_URL'] = url
    environ['DB_DIRECTORY'] = db_dir

    if not isdir(db_dir) and not exists(db_dir):
        mkdir(db_dir)
    elif not isdir(db_dir) and exists(db_dir):
        print("[utxoplugin] ERROR: " + db_dir + " exists and is not a directory. Requiring manual deletion.")
        sys.exit(1)

    env = Env(coin=MappedCoin)

    print("[utxoplugin] Coin: {}, Port: {}, Daemon RPC Port: {}".format(coin, port, rpc_port))
    print("[utxoplugin] Using URL\n{}".format(url))

    env.rpc_port = port
    print("[utxoplugin] Starting RPC on port " + str(env.rpc_port))

    if not db_compacted and skip_compacting != 'true':
        print('[utxoplugin] compacting db history')

        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(compact_history(env))
        except Exception:
            traceback.print_exc()
            print('[utxoplugin] History compaction terminated abnormally')
        else:
            print('[utxoplugin] History compaction complete')

        del env
        return main(db_compacted=True)

    log_fmt = env.default('LOG_FORMAT', '%(levelname)s:%(name)s:%(message)s')
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(CompactFormatter(log_fmt))
    make_logger('electrumx', handler=handler, level=logging.DEBUG)

    logging.info('ElectrumX server starting')

    server = Controller(env)
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
