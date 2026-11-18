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
 * Which kernel and initramfs files the VM manager accepts for a protected VM started from the system partition:
 * the types of check_label_is_allowed in packages/modules/Virtualization/android/virtmgr/src/virtualmachine.rs.
 * The product takes system_file alone (the virtualization APEX), so it can never start from /data/local/tmp. The
 * self-test (test, debuggable builds) also takes shell_data_file. App data is never accepted. virtmgr checks again.
 */
final class VmImages {
    private VmImages() {}

    // virtmgr's list (check_label_is_allowed). The product and the test take only part of it.
    private static final String[] VIRTMGR = {
        "apk_data_file", "shell_data_file", "staging_data_file", "apex_dm_device", "system_file",
        "virtualizationservice_data_file", "vendor_microdroid_file",
    };

    /** label: an SELinux context, user:role:type:level with an optional category part. As virtmgr takes it. */
    static boolean virtmgrAllows(String label) {
        String type = type(label);
        for (String a : VIRTMGR) {
            if (a.equals(type)) return true;
        }
        return false;
    }

    /** What this service starts from: system_file, and for the self-test also shell_data_file. */
    static boolean labelAllowed(String label, boolean test) {
        String type = type(label);
        return "system_file".equals(type) || (test && "shell_data_file".equals(type));
    }

    private static String type(String label) {
        if (label == null) return null;
        String[] parts = label.split(":", -1);
        return parts.length == 4 || parts.length == 5 ? parts[2] : null;
    }
}
