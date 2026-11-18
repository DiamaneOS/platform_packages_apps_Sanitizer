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

import android.os.Build;
import android.os.SystemProperties;

/**
 * Whether this is a debuggable build (ro.debuggable is 1: userdebug or eng), as an app can tell. An app may not read
 * ro.debuggable itself (its SELinux label is for userdebug_or_eng), so a direct read answers false even on a
 * userdebug build. The zygote reads it into Build.IS_DEBUGGABLE before any app starts, so that value is used (a field
 * kept for apps that use it), and when it cannot be reached, the build type, which a user build always gives as
 * "user". Test switches below honour nothing on a user build.
 */
final class DebugBuild {
    private DebugBuild() {}

    static boolean debuggable() {
        try {
            return Build.class.getField("IS_DEBUGGABLE").getBoolean(null);
        } catch (ReflectiveOperationException | RuntimeException e) {
            return "userdebug".equals(Build.TYPE) || "eng".equals(Build.TYPE);
        }
    }

    // A test holds the decoder VM down until this time (seconds since the epoch), debuggable builds only. For example
    // adb shell setprop debug.diamaneos.decoder.down_until $(($(adb shell date +%s) + 60)) holds it for a minute.
    static final String DOWN_UNTIL = "debug.diamaneos.decoder.down_until";

    // A test compares the old single lane with the two lanes: "1" here (set before the service starts) gives one lane
    // and one vCPU. Debuggable builds only.
    static final String SINGLE_LANE = "debug.diamaneos.decoder.single_lane";

    /** Debuggable builds only: whether a test asked for the single lane. Never on a user build. */
    static boolean singleLaneForTest() {
        return debuggable() && SystemProperties.getBoolean(SINGLE_LANE, false);
    }

    /** Debuggable builds only: timing lines per request in the log (lane, queue wait, VM time). */
    static boolean timingLog() {
        return debuggable();
    }

    /** Debuggable builds only: whether a test holds the decoder VM down now. Never on a user build. */
    static boolean vmHeldDown() {
        if (!debuggable()) return false;
        long until = SystemProperties.getLong(DOWN_UNTIL, 0);
        return until > 0 && System.currentTimeMillis() / 1000 < until;
    }
}
