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
 * The service's images are system_file (the virtualization APEX), the self-test's shell_data_file (/data/local/tmp,
 * debuggable builds). App data is never accepted.
 */
final class VmImages {
    private VmImages() {}

    private static final String[] ALLOWED = {
        "apk_data_file", "shell_data_file", "staging_data_file", "apex_dm_device", "system_file",
        "virtualizationservice_data_file", "vendor_microdroid_file",
    };

    /** label: an SELinux context, user:role:type:level with an optional category part. */
    static boolean labelAllowed(String label) {
        if (label == null) return false;
        String[] parts = label.split(":", -1);
        if (parts.length != 4 && parts.length != 5) return false;
        for (String a : ALLOWED) {
            if (a.equals(parts[2])) return true;
        }
        return false;
    }
}
