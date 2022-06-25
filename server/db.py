from aiorpcx import run_in_thread
from electrumx.server.db import DB


class Database(DB):
    def __init__(self, env):
        super().__init__(env)

    async def raw_block(self, height):
        if height < 0:
            raise self.DBError(f'{height:,d} not on disk')

        def get_block():
            try:
                return height, bytes(self.read_raw_block(height)).hex()
            except FileNotFoundError:
                return None, None

        return await run_in_thread(get_block)

    async def raw_blocks(self, last_height, count):
        if last_height < 0 or count < 0:
            raise self.DBError(f'{count:,d} blocks starting at '
                               f'{last_height:,d} not on disk')

        def get_blocks():
            heights = range(last_height, last_height - count, -1)
            try:
                return [(height, bytes(self.read_raw_block(height)).hex()) for height in heights]
            except FileNotFoundError:
                return []

        return await run_in_thread(get_blocks)
