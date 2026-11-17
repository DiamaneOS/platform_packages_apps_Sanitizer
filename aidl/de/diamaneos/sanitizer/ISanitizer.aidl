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
 * The file sanitizer inside a protected VM. Android sends the untrusted file and gets back only plain pixels, so
 * Android's own decoders never parse the attacker's bytes.
 */
interface ISanitizer {
    /** vsock port of the service in the VM. */
    const int PORT = 5684;

    /** Largest result in pixels. Larger JPEGs are scaled down while decoding, other formats are refused. */
    const int MAX_PIXELS = 8388608;

    /** Largest input file in bytes. */
    const int MAX_INPUT_BYTES = 33554432;

    /** Largest piece of a transfer in bytes: binder over vsock refuses large transactions. */
    const int CHUNK = 65536;

    /** Appends a piece of the input file, at most CHUNK bytes. */
    void addInput(in byte[] piece);

    /**
     * Decodes the PNG or JPEG file collected with addInput and drops it. Returns the length of the result:
     * "DSR1", the width and the height as little-endian 32-bit numbers, then width * height pixels as premultiplied
     * RGBA bytes.
     */
    long decode();

    /** Returns at most CHUNK bytes of the result, from offset. */
    byte[] readResult(long offset);
}
