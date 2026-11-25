/**
 * AML Sentinel — Enterprise Client-Side Server-State Engine (`window.SentinelQuery`)
 * ==================================================================================
 * Zero-dependency TanStack-Query-inspired server-state manager loaded across all 14 workspace pages:
 *  1. In-memory bounded LRU SWR cache (zero PII ever persisted to localStorage/disk)
 *  2. In-flight request deduplication (coalesces concurrent identical query keys into 1 request)
 *  3. Conditional HTTP revalidation (`If-None-Match` -> `304 Not Modified`) using in-memory ETags
 *  4. Automatic race-condition cancellation via per-lane `AbortController` (`abortKey`)
 *  5. Optimistic mutations with atomic snapshot rollback + targeted invalidation
 *  6. Cross-tab cache invalidation via `BroadcastChannel('aml_sentinel_cache')`
 */
(function () {
    'use strict';

    if (window.SentinelQuery) return;

    const MAX_CACHE_ENTRIES = 128;
    const DEFAULT_STALE_TIME_MS = 15000;
    const CACHE_CHANNEL_NAME = 'aml_sentinel_cache';
    const TAB_ID = `sq-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

    // LRU Map<serializedKey, { key, data, etag, updatedAt, invalidated }>
    const cache = new Map();
    // Map<serializedKey, Promise>
    const inflight = new Map();
    // Map<abortKey, AbortController>
    const abortLanes = new Map();
    // Map<serializedKey, Set<function>>
    const subscribers = new Map();
    // Set<{ prefix: string[], callback: function }>
    const invalidationListeners = new Set();

    let cacheChannel = null;
    let hiddenSince = null;

    function normalizeKey(key) {
        return Array.isArray(key) ? key.map((part) => (part === undefined ? null : part)) : [String(key)];
    }

    function serializeKey(key) {
        return JSON.stringify(normalizeKey(key));
    }

    function keyStartsWith(candidateArr, prefixArr) {
        if (prefixArr.length > candidateArr.length) return false;
        for (let i = 0; i < prefixArr.length; i++) {
            if (JSON.stringify(candidateArr[i]) !== JSON.stringify(prefixArr[i])) {
                return false;
            }
        }
        return true;
    }

    function touchLru(sKey, entry) {
        cache.delete(sKey);
        cache.set(sKey, entry);
        while (cache.size > MAX_CACHE_ENTRIES) {
            const oldestKey = cache.keys().next().value;
            if (oldestKey === undefined) break;
            cache.delete(oldestKey);
        }
    }

    function notifySubscribers(sKey, entry) {
        const subs = subscribers.get(sKey);
        if (!subs || !subs.size) return;
        subs.forEach((fn) => {
            try { fn(entry ? entry.data : undefined, entry || null); } catch (e) { console.debug('SentinelQuery subscriber error:', e); }
        });
    }

    function cloneSnapshot(val) {
        if (val === null || val === undefined || typeof val !== 'object') return val;
        if (typeof structuredClone === 'function') {
            try { return structuredClone(val); } catch (_) { /* fallback below */ }
        }
        try { return JSON.parse(JSON.stringify(val)); } catch (_) { return val; }
    }

    function broadcastInvalidation(prefixes) {
        if (!cacheChannel) return;
        try {
            cacheChannel.postMessage({ sender: TAB_ID, type: 'INVALIDATE', prefixes });
        } catch (_) { /* ignore */ }
    }

    function invalidateLocal(prefixKey, { broadcast = false } = {}) {
        const prefixArr = normalizeKey(prefixKey);
        const matchedEntries = [];
        cache.forEach((entry, sKey) => {
            if (keyStartsWith(entry.key, prefixArr)) {
                entry.invalidated = true;
                entry.updatedAt = 0;
                matchedEntries.push(sKey);
            }
        });
        invalidationListeners.forEach((listener) => {
            if (keyStartsWith(prefixArr, listener.prefix) || keyStartsWith(listener.prefix, prefixArr)) {
                try { listener.callback(prefixArr); } catch (e) { console.debug('SentinelQuery invalidation listener error:', e); }
            }
        });
        if (broadcast) {
            broadcastInvalidation([prefixArr]);
        }
        return matchedEntries.length;
    }

    if (typeof BroadcastChannel !== 'undefined') {
        try {
            cacheChannel = new BroadcastChannel(CACHE_CHANNEL_NAME);
            cacheChannel.onmessage = (e) => {
                const msg = e.data;
                if (!msg || msg.sender === TAB_ID) return;
                if (msg.type === 'INVALIDATE' && Array.isArray(msg.prefixes)) {
                    msg.prefixes.forEach((p) => invalidateLocal(p, { broadcast: false }));
                }
            };
        } catch (_) { cacheChannel = null; }
    }

    // Mark cached snapshots stale when coming back online or returning after >60s hidden
    window.addEventListener('online', () => {
        cache.forEach((entry) => { entry.updatedAt = 0; entry.invalidated = true; });
        invalidationListeners.forEach((l) => {
            try { l.callback(l.prefix); } catch (_) { /* ignore */ }
        });
    });
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            hiddenSince = Date.now();
        } else if (hiddenSince && Date.now() - hiddenSince > 60000) {
            hiddenSince = null;
            cache.forEach((entry) => { entry.updatedAt = 0; });
        } else {
            hiddenSince = null;
        }
    });

    function abortLane(abortKey) {
        if (!abortKey) return null;
        const prev = abortLanes.get(abortKey);
        if (prev) {
            try { prev.abort(new DOMException('Superseded by newer request', 'AbortError')); } catch (_) { /* ignore */ }
        }
        const next = new AbortController();
        abortLanes.set(abortKey, next);
        return next;
    }

    async function fetchQuery(key, queryFn, options = {}) {
        const keyArr = normalizeKey(key);
        const sKey = serializeKey(keyArr);
        const staleTime = options.staleTime !== undefined ? Number(options.staleTime) : DEFAULT_STALE_TIME_MS;
        const force = Boolean(options.force);
        const abortKey = options.abortKey || null;

        const existing = cache.get(sKey);
        const isFresh = Boolean(
            existing &&
            !existing.invalidated &&
            !force &&
            (Date.now() - existing.updatedAt) < staleTime
        );
        if (isFresh) {
            touchLru(sKey, existing);
            return existing.data;
        }

        // Coalesce concurrent identical requests (unless a dedicated abortLane explicitly cancels superseded queries)
        if (!abortKey && !force && inflight.has(sKey)) {
            return inflight.get(sKey);
        }

        const controller = abortLane(abortKey);
        const signal = options.signal || (controller ? controller.signal : undefined);

        const promise = Promise.resolve()
            .then(() => queryFn({ signal, etag: existing ? existing.etag : null, cachedData: existing ? existing.data : undefined }))
            .then((result) => {
                // Support both raw data returns and `{ data, etag, notModified }` envelopes
                let nextData = result;
                let nextEtag = existing ? existing.etag : null;
                if (result && typeof result === 'object' && result.__sentinelEnvelope === true) {
                    nextData = result.notModified && existing ? existing.data : result.data;
                    nextEtag = result.etag || nextEtag;
                }
                const entry = {
                    key: keyArr,
                    data: nextData,
                    etag: nextEtag,
                    updatedAt: Date.now(),
                    invalidated: false,
                };
                touchLru(sKey, entry);
                notifySubscribers(sKey, entry);
                return entry.data;
            })
            .finally(() => {
                if (inflight.get(sKey) === promise) {
                    inflight.delete(sKey);
                }
                if (abortKey && controller && abortLanes.get(abortKey) === controller) {
                    abortLanes.delete(abortKey);
                }
            });

        if (!abortKey) {
            inflight.set(sKey, promise);
        }
        return promise;
    }

    async function fetchJson(key, url, options = {}) {
        const fetchOptions = Object.assign({}, options.fetchOptions || {});
        const onBackgroundUpdate = typeof options.onUpdate === 'function' ? options.onUpdate : null;
        const swr = Boolean(options.swr);
        const sKey = serializeKey(key);
        const cached = cache.get(sKey);

        const runNetwork = () => fetchQuery(
            key,
            async ({ signal, etag }) => {
                const headers = new Headers(fetchOptions.headers || {});
                if (!headers.has('Accept')) headers.set('Accept', 'application/json');
                if (etag && !options.skipConditional && !headers.has('If-None-Match')) {
                    headers.set('If-None-Match', etag);
                }
                const reqOpts = Object.assign({}, fetchOptions, { method: 'GET', headers, signal, credentials: 'include' });
                const res = await fetch(url, reqOpts);
                if (res.status === 304) {
                    return {
                        __sentinelEnvelope: true,
                        notModified: true,
                        data: null,
                        etag: res.headers.get('ETag') || etag
                    };
                }
                if (!res.ok) {
                    if (window.SentinelApi && typeof window.SentinelApi.parseApiError === 'function') {
                        throw await window.SentinelApi.parseApiError(res);
                    }
                    throw new Error(`HTTP ${res.status}`);
                }
                const ct = res.headers.get('Content-Type') || '';
                const data = ct.includes('application/json') ? await res.json() : await res.text();
                return {
                    __sentinelEnvelope: true,
                    notModified: false,
                    data,
                    etag: res.headers.get('ETag') || null
                };
            },
            options
        );

        // Stale-While-Revalidate: return stale snapshot immediately and revalidate asynchronously
        if (swr && cached && cached.data !== undefined && !options.force) {
            const staleTime = options.staleTime !== undefined ? Number(options.staleTime) : DEFAULT_STALE_TIME_MS;
            if (cached.invalidated || (Date.now() - cached.updatedAt) >= staleTime) {
                runNetwork()
                    .then((fresh) => { if (onBackgroundUpdate) onBackgroundUpdate(fresh); })
                    .catch((err) => { if (!err || err.name !== 'AbortError') console.debug('SWR revalidation skipped:', err); });
            }
            return cached.data;
        }

        return runNetwork();
    }

    function getQueryData(key) {
        const entry = cache.get(serializeKey(key));
        return entry ? entry.data : undefined;
    }

    function getQueryMeta(key) {
        const entry = cache.get(serializeKey(key));
        return entry ? { etag: entry.etag, updatedAt: entry.updatedAt, invalidated: entry.invalidated } : null;
    }

    function setQueryData(key, updater, { etag } = {}) {
        const keyArr = normalizeKey(key);
        const sKey = serializeKey(keyArr);
        const prev = cache.get(sKey);
        const prevData = prev ? prev.data : undefined;
        const nextData = typeof updater === 'function' ? updater(prevData) : updater;
        const entry = {
            key: keyArr,
            data: nextData,
            etag: etag !== undefined ? etag : (prev ? prev.etag : null),
            updatedAt: Date.now(),
            invalidated: false,
        };
        touchLru(sKey, entry);
        notifySubscribers(sKey, entry);
        return nextData;
    }

    async function mutate({
        mutationFn,
        optimisticKey = null,
        optimisticUpdater = null,
        onMutate = null,
        onError = null,
        onSuccess = null,
        invalidateKeys = [],
        broadcast = true,
    }) {
        const snapshots = new Map();
        if (optimisticKey && typeof optimisticUpdater === 'function') {
            const sKey = serializeKey(optimisticKey);
            const prev = cache.get(sKey);
            snapshots.set(sKey, prev ? { key: prev.key, data: cloneSnapshot(prev.data), etag: prev.etag } : null);
            setQueryData(optimisticKey, optimisticUpdater);
        }

        let customContext = undefined;
        if (typeof onMutate === 'function') {
            customContext = await onMutate();
        }

        try {
            const result = await mutationFn();
            if (typeof onSuccess === 'function') {
                await onSuccess(result, customContext);
            }
            if (Array.isArray(invalidateKeys) && invalidateKeys.length) {
                const normalizedPrefixes = [];
                invalidateKeys.forEach((prefix) => {
                    invalidateLocal(prefix, { broadcast: false });
                    normalizedPrefixes.push(normalizeKey(prefix));
                });
                if (broadcast) {
                    broadcastInvalidation(normalizedPrefixes);
                }
            }
            return result;
        } catch (err) {
            // Roll back optimistic cache snapshot cleanly on rejection
            snapshots.forEach((snap, sKey) => {
                if (snap === null) {
                    cache.delete(sKey);
                    notifySubscribers(sKey, null);
                } else {
                    const restored = { key: snap.key, data: snap.data, etag: snap.etag, updatedAt: Date.now(), invalidated: false };
                    touchLru(sKey, restored);
                    notifySubscribers(sKey, restored);
                }
            });
            if (typeof onError === 'function') {
                await onError(err, customContext);
            }
            throw err;
        }
    }

    function invalidateQueries(prefixKey, opts = { broadcast: true }) {
        return invalidateLocal(prefixKey, { broadcast: opts.broadcast !== false });
    }

    function subscribe(key, listener) {
        const sKey = serializeKey(key);
        if (!subscribers.has(sKey)) subscribers.set(sKey, new Set());
        subscribers.get(sKey).add(listener);
        return () => {
            const set = subscribers.get(sKey);
            if (set) {
                set.delete(listener);
                if (!set.size) subscribers.delete(sKey);
            }
        };
    }

    function onInvalidate(prefixKey, callback) {
        const entry = { prefix: normalizeKey(prefixKey), callback };
        invalidationListeners.add(entry);
        return () => invalidationListeners.delete(entry);
    }

    function cancelQueries(abortKey) {
        const ctrl = abortLanes.get(abortKey);
        if (ctrl) {
            try { ctrl.abort(new DOMException('Cancelled', 'AbortError')); } catch (_) { /* ignore */ }
            abortLanes.delete(abortKey);
        }
    }

    function clear() {
        cache.clear();
        inflight.clear();
        abortLanes.forEach((ctrl) => {
            try { ctrl.abort(new DOMException('Cache cleared', 'AbortError')); } catch (_) { /* ignore */ }
        });
        abortLanes.clear();
    }

    window.SentinelQuery = {
        fetchQuery,
        fetchJson,
        getQueryData,
        getQueryMeta,
        setQueryData,
        mutate,
        invalidateQueries,
        subscribe,
        onInvalidate,
        cancelQueries,
        clear,
    };
})();
