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
 * The mount table, read for one question: may the decoder thread read this file while it streams it to the VM. Only
 * a device the table names as a local file system of the internal storage qualifies. A device the table does not
 * show at all (another mount namespace, an internal mount) never does.
 */
final class Mounts {
    private Mounts() {}

    // Local file systems of the internal storage: a read on them cannot stall without end.
    private static final String[] LOCAL = {"f2fs", "ext4", "erofs"};

    /** dev_t as the kernel encodes it (new_encode_dev): the major and minor number. */
    static int major(long dev) {
        return (int) (((dev >>> 8) & 0xfff) | ((dev >>> 32) & ~0xfffL));
    }

    static int minor(long dev) {
        return (int) ((dev & 0xff) | ((dev >>> 12) & ~0xffL));
    }

    /**
     * Every mount of device major:minor (field 3 of a mountinfo line) has a local file system type, and there is at
     * least one. Not found, or any mount of it of another type (FUSE passes a device of its own, never this one):
     * false. A removable drive (an SD card or USB drive vold mounts as a public volume, from /dev/block/vold/public:
     * at /mnt/media_rw/) is never local, whatever its file system: it can stall or go away mid-read.
     */
    static boolean localDevice(int major, int minor, String mountinfo) {
        String want = major + ":" + minor;
        boolean found = false;
        for (String line : mountinfo.split("\n")) {
            String[] fields = line.split(" ");
            if (fields.length < 7 || !fields[2].equals(want)) continue;
            int dash = -1;
            for (int i = 6; i < fields.length; i++) {
                if (fields[i].equals("-")) {
                    dash = i;
                    break;
                }
            }
            if (dash < 0 || dash + 1 >= fields.length) return false;
            String source = dash + 2 < fields.length ? fields[dash + 2] : "";
            if (source.startsWith("/dev/block/vold/public:") || fields[4].startsWith("/mnt/media_rw/")) return false;
            boolean local = false;
            for (String t : LOCAL) local |= t.equals(fields[dash + 1]);
            if (!local) return false;
            found = true;
        }
        return found;
    }
}
