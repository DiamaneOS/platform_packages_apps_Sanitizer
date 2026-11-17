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

/** The mount table, read for one question: is a file on FUSE. As MediaProvider's vmdecode Mounts. */
final class Mounts {
    private Mounts() {}

    /** The file system of the deepest mount point holding path (the last one mounted there) is FUSE. */
    static boolean isFuse(String path, String mountinfo) {
        if (path == null || !path.startsWith("/")) return false;
        String bestPoint = null;
        String bestType = null;
        for (String line : mountinfo.split("\n")) {
            String[] fields = line.split(" ");
            if (fields.length < 7) continue;
            int dash = -1;
            for (int i = 6; i < fields.length; i++) {
                if (fields[i].equals("-")) {
                    dash = i;
                    break;
                }
            }
            if (dash < 0 || dash + 1 >= fields.length) continue;
            String point = fields[4].replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n")
                    .replace("\\134", "\\");
            boolean holds = point.equals("/") || path.equals(point) || path.startsWith(point + "/");
            if (!holds) continue;
            if (bestPoint == null || point.length() >= bestPoint.length()) {
                bestPoint = point;
                bestType = fields[dash + 1];
            }
        }
        return bestType != null && bestType.startsWith("fuse");
    }
}
