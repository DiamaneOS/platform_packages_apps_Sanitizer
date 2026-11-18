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

import java.util.Arrays;

/** The packages that may call the decode service (DecodeService.checkCaller), besides the system uid. */
final class Callers {
    private Callers() {}

    static final String[] PRODUCTION = {
        "com.android.providers.media.module",
        "com.android.systemui",
    };

    // The device tests of the frameworks decode client (DiamaneOSDecodeClientTests, platform-signed like this app, so
    // the DECODE permission is theirs), so that they reach the VM. Debuggable builds only, like the other test hooks
    // (DebugBuild): never a caller on a user build.
    static final String CLIENT_TESTS = "de.diamaneos.decode.client.tests";

    /** A fresh list: the production callers, and on a debuggable build the client tests too. */
    static String[] allowed(boolean debuggable) {
        if (!debuggable) return PRODUCTION.clone();
        String[] callers = Arrays.copyOf(PRODUCTION, PRODUCTION.length + 1);
        callers[PRODUCTION.length] = CLIENT_TESTS;
        return callers;
    }
}
