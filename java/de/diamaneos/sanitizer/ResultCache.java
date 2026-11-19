/*
 * Copyright (C) 2026 DiamaneOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.diamaneos.sanitizer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Checked VM answers by the content of the file: SHA-256 of the bytes plus the operation, its arguments and the
 * Android user who asked. Asking again for the same file costs nothing. Per user, so the time an answer takes does not
 * tell one user (or profile) what another one decoded lately. Only answers that passed every check are stored, and only
 * clean answers (OK, UNSUPPORTED, INVALID), never "unavailable". Bounded in bytes, least recently used out first.
 */
final class ResultCache {
    static final long MAX_BYTES = 24L << 20;
    static final int MAX_ENTRY_BYTES = 4 << 20;

    private static final class Key {
        final byte[] digest;
        final int op, a, b, user;

        Key(byte[] digest, int op, int a, int b, int user) {
            this.digest = digest;
            this.op = op;
            this.a = a;
            this.b = b;
            this.user = user;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Key)) return false;
            Key k = (Key) o;
            return op == k.op && a == k.a && b == k.b && user == k.user && Arrays.equals(digest, k.digest);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(digest) * 31 + op * 7 + a * 3 + b + user * 1009;
        }
    }

    private final LinkedHashMap<Key, GuestLink.Answer> mMap = new LinkedHashMap<>(64, 0.75f, true);
    private long mBytes;

    static byte[] digest(byte[] file, int len) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(file, 0, len);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static Object key(byte[] digest, int op, int a, int b, int user) {
        return new Key(digest, op, a, b, user);
    }

    synchronized GuestLink.Answer get(Object key) {
        return mMap.get((Key) key);
    }

    synchronized void put(Object key, GuestLink.Answer answer) {
        long size = sizeOf(answer);
        if (size > MAX_ENTRY_BYTES) return;
        GuestLink.Answer old = mMap.put((Key) key, answer);
        if (old != null) mBytes -= sizeOf(old);
        mBytes += size;
        Iterator<Map.Entry<Key, GuestLink.Answer>> it = mMap.entrySet().iterator();
        while (mBytes > MAX_BYTES && it.hasNext()) {
            mBytes -= sizeOf(it.next().getValue());
            it.remove();
        }
    }

    synchronized void clear() {
        mMap.clear();
        mBytes = 0;
    }

    private static long sizeOf(GuestLink.Answer a) {
        return 1024 + (a.pixels != null ? a.pixels.length : 0) + (a.gainPixels != null ? a.gainPixels.length : 0);
    }
}
