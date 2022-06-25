from electrumx.server.session import SessionManager


class SessionManagerMixin(SessionManager):
    def __init__(self, env, db, bp, daemon, mempool, shutdown_event):
        super().__init__(env, db, bp, daemon, mempool, shutdown_event)
        self.bsub_results = None
        self._cache_counter = 0

    async def _notify_sessions(self, height, touched):
        self._cache_counter += 1
        for cache in (self._tx_hashes_cache, self._merkle_cache):
            for key in range(height, self.db.db_height + 1):
                if key in cache:
                    del cache[key]

        height_changed = height != self.notified_height
        if height_changed:
            await self._refresh_hsub_results(height)
            await self._refresh_bsub_results(height)

            # Invalidate our history cache for touched hashXs
            cache = self._history_cache
            for hashX in set(cache).intersection(touched):
                del cache[hashX]

        for session in self.sessions:
            await self._task_group.spawn(session.notify, touched, height_changed)

    async def _refresh_bsub_results(self, height):
        '''Refresh cached raw block'''
        height = min(height, self.db.db_height)
        h, raw = await self.db.raw_block(height)
        self.bsub_results = {'hex': raw, 'height': height}
        self.logger.info('Updated block subscription height: {}'.format(height))
