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

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "proto.h"

namespace decoder {

// Fills the EXIF and XMP fields of m from a file of the given format. m must be zeroed with orientation -1 first.
// Uses no memory but the stack (HEIF and AVIF: the arena for the box index), so it runs in the locked-down worker.
void read_metadata(const uint8_t* data, size_t size, uint32_t format, Meta* m);

// One EXIF block (a TIFF header and its IFDs) and one XMP packet, for the containers that keep them as items.
void read_exif_block(const uint8_t* data, size_t size, Meta* m);
void read_xmp_block(const uint8_t* data, size_t size, Meta* m);

// HEIF and AVIF (fmt_heif.cpp): the Exif and XMP items of the primary image, and its orientation from irot and
// imir (the file's EXIF orientation is not used, as the format says).
void heif_metadata(const uint8_t* data, size_t size, Meta* m);

// True when a PNG carries an acTL chunk before its image data (an animated PNG).
bool png_is_animated(const uint8_t* data, size_t size);

}  // namespace decoder
