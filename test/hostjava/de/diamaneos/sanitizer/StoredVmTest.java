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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** StoredVm against a VM manager stand-in that records its calls. */
@RunWith(JUnit4.class)
public final class StoredVmTest {
    private static final class FakeSlot implements StoredVm.Slot<String> {
        final List<String> calls = new ArrayList<>();
        String stored;          // what get() returns
        boolean getThrows;      // a stored config that does not load
        int createFailures;     // creates that fail before one succeeds

        @Override public String get() throws Exception {
            calls.add("get");
            if (getThrows) {
                throw new IllegalStateException("Persisted VM config is invalid",
                        new NullPointerException("payloadBinaryName must not be null"));
            }
            return stored;
        }

        @Override public void close(String vm) {
            calls.add("close " + vm);
        }

        @Override public void delete() {
            calls.add("delete");
            stored = null;
            getThrows = false;
        }

        @Override public String create() throws Exception {
            calls.add("create");
            if (createFailures > 0) {
                createFailures--;
                throw new IllegalStateException("exists");
            }
            stored = "new";
            return stored;
        }
    }

    private final List<String> mWarnings = new ArrayList<>();
    private final StoredVm.Log mLog = (message, cause) -> mWarnings.add(message + ": " + cause.getMessage());

    @Test
    public void nothingStored_createsOnly() throws Exception {
        FakeSlot s = new FakeSlot();
        assertEquals("new", StoredVm.fresh(s, mLog));
        assertEquals(List.of("get", "create"), s.calls);
        assertEquals(0, mWarnings.size());
    }

    @Test
    public void storedVm_closedDeletedAndMadeAgain() throws Exception {
        FakeSlot s = new FakeSlot();
        s.stored = "old";
        assertEquals("new", StoredVm.fresh(s, mLog));
        assertEquals(List.of("get", "close old", "delete", "create"), s.calls);
        assertEquals(0, mWarnings.size());
    }

    @Test
    public void unreadableConfig_deletedWithoutLoadingAndMadeAgain() throws Exception {
        FakeSlot s = new FakeSlot();
        s.getThrows = true;
        assertEquals("new", StoredVm.fresh(s, mLog));
        assertEquals(List.of("get", "delete", "create"), s.calls);
        assertEquals(List.of("the stored VM does not load, deleting it: Persisted VM config is invalid"), mWarnings);
    }

    @Test
    public void failedCreate_triedOnceMore() throws Exception {
        FakeSlot s = new FakeSlot();
        s.createFailures = 1;
        assertEquals("new", StoredVm.fresh(s, mLog));
        assertEquals(List.of("get", "create", "delete", "create"), s.calls);
        assertEquals(1, mWarnings.size());
    }

    @Test
    public void secondFailedCreate_reachesTheCaller() {
        FakeSlot s = new FakeSlot();
        s.getThrows = true;
        s.createFailures = 2;
        assertThrows(IllegalStateException.class, () -> StoredVm.fresh(s, mLog));
        assertEquals(List.of("get", "delete", "create", "delete", "create"), s.calls);
    }
}
