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

/**
 * The decoder VM's slot in the VM manager, made fresh for each start. The VM manager keeps a VM's config from one
 * start to the next, and a config an older build stored may not load after an update (2026-11-19: "Persisted VM config
 * is invalid" from a config without a payload binary name). The stored VM is then deleted and made again, once, and
 * the reason goes to the log. Plain Java behind {@link Slot}, so the host test can drive it.
 */
final class StoredVm {
    private StoredVm() {}

    /** The VM manager's calls for one VM name. */
    interface Slot<V> {
        /** The stored VM, or null when there is none. Throws when it is stored but cannot be loaded. */
        V get() throws Exception;

        void close(V vm) throws Exception;

        /** Deletes the stored VM and its files, without loading it. */
        void delete() throws Exception;

        V create() throws Exception;
    }

    interface Log {
        void warn(String message, Throwable cause);
    }

    /** Deletes whatever is stored under the name and creates the VM anew. */
    static <V> V fresh(Slot<V> slot, Log log) throws Exception {
        V old;
        try {
            old = slot.get();
        } catch (Exception e) {
            log.warn("the stored VM does not load, deleting it", e);
            slot.delete();
            return createOnce(slot, log);
        }
        if (old != null) {
            slot.close(old);
            slot.delete();
        }
        return createOnce(slot, log);
    }

    // A create that fails on what is left of an earlier VM (its files, a config of another build) gets one more try
    // after a delete. The second failure is the caller's.
    private static <V> V createOnce(Slot<V> slot, Log log) throws Exception {
        try {
            return slot.create();
        } catch (Exception e) {
            log.warn("creating the VM failed, deleting what is stored and trying once more", e);
            slot.delete();
            return slot.create();
        }
    }
}
