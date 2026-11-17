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
 * Android's own decoders never parse the attacker's bytes. Inside the VM every file is decoded by a fresh worker
 * process that can only read, write and exit. One request at a time: a new addInput or decode ends the previous one.
 */
interface ISanitizer {
    /** vsock port of the service in the VM. */
    const int PORT = 5684;

    /** Largest result in pixels. Larger images are scaled down while decoding. */
    const int MAX_PIXELS = 8388608;

    /** Largest width or height of an input image and of a result. */
    const int MAX_SIDE = 16384;

    /** Largest input file in bytes. */
    const int MAX_INPUT_BYTES = 33554432;

    /** Largest piece of a transfer in bytes: binder over vsock refuses large transactions. */
    const int CHUNK = 65536;

    /** Starts a new input file of the given size in bytes, at most MAX_INPUT_BYTES. */
    void begin(int size);

    /** Appends a piece of the input file, at most CHUNK bytes. */
    void addInput(in byte[] piece);

    /**
     * Decodes the PNG or JPEG file collected with addInput in a fresh worker and drops the file. maxSide 0 asks for
     * the full size, scaled down to MAX_PIXELS at most, otherwise neither side of the result is longer than maxSide.
     * Returns the 12-byte header: "DSR1", then the width and the height as little-endian 32-bit numbers.
     */
    byte[] decode(int maxSide);

    /**
     * Returns the next part of the pixels, at most CHUNK bytes of premultiplied RGBA rows from the top. After
     * width * height * 4 bytes, returns an empty array if the worker ended cleanly, an error otherwise.
     */
    byte[] readPixels();
}
