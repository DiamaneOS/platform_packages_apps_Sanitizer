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

// The wire protocol between the decode service on Android and the broker in the protected VM, over one vsock stream.
// Little endian, fixed headers, one request and one reply at a time. Android parses only these headers, the pixels
// (whose length the header fixes) and the fixed metadata record. GuestLink.java mirrors every constant here.
//
//   request:  Request header, then inputLen bytes of the file.
//   reply:    Reply header, then payloadLen bytes, then an End trailer. A worker that fails after the header was
//             sent makes the broker close the connection instead of sending the trailer.

#pragma once

#include <stdint.h>

namespace decoder {

constexpr uint32_t kPort = 5685;

constexpr uint32_t kRequestMagic = 0x31305144;  // "DQ01"
constexpr uint32_t kReplyMagic = 0x31305344;    // "DS01"
constexpr uint32_t kEndMagic = 0x31304544;      // "DE01"
constexpr uint32_t kMetaMagic = 0x31304d44;     // "DM01"

enum Op : uint32_t {
    kOpPing = 1,       // no input, reply payload 0
    kOpProbe = 2,      // format, size, animation (GIF, WebP, PNG, HEIF and AVIF only), no pixels
    kOpThumbnail = 3,  // pixels fitting arg0 x arg1, payload width * height * 4 premultiplied RGBA
    kOpMetadata = 4,   // payload: one Meta record
    kOpHook = 5,       // test builds only: arg0 selects a lockdown hook
};

enum Status : int32_t {
    kOk = 0,
    kUnsupported = 2,  // not a format the VM decodes, or a kind of it the VM does not decode (a 10-bit HEIF)
    kInvalid = 3,      // broken or hostile file, or a limit was hit
    kInternal = 4,     // the broker itself failed (no pipe, no fork)
};

// The contract's FORMAT_* values (IDecodeService.aidl).
enum Format : uint32_t {
    kFormatUnknown = 0,
    kFormatJpeg = 1,
    kFormatPng = 2,
    kFormatGif = 3,
    kFormatWebp = 4,
    kFormatBmp = 5,
    kFormatHeif = 6,
    kFormatAvif = 7,
    kFormatDng = 8,
    kFormatIco = 9,
    kFormatWbmp = 10,
};

constexpr uint32_t kMaxInputBytes = 32u << 20;
constexpr uint32_t kMaxDimension = 65535;
constexpr uint32_t kMaxPixels = 8u << 20;

struct Request {
    uint32_t magic;
    uint32_t op;
    uint32_t arg0;  // thumbnail: max width, hook: hook number
    uint32_t arg1;  // thumbnail: max height
    uint32_t inputLen;
    uint32_t reserved[3];
};
static_assert(sizeof(Request) == 32);

struct Reply {
    uint32_t magic;
    int32_t status;
    uint32_t format;
    uint32_t width;
    uint32_t height;
    uint32_t extra;  // probe: 1 when animated, thumbnail: rotation in degrees
    uint32_t payloadLen;
    uint32_t reserved;
};
static_assert(sizeof(Reply) == 32);

struct End {
    uint32_t magic;
    int32_t status;  // 0: the worker ended cleanly
};
static_assert(sizeof(End) == 8);

// Text fields are NUL-padded. Android checks every byte against the field's rule and rejects the whole record when
// one field breaks it.
constexpr uint32_t kTextChars = 256;   // printable ASCII
constexpr uint32_t kNumberChars = 32;  // 0-9 . / space
constexpr uint32_t kIdChars = 128;     // A-Z a-z 0-9 : . - _

enum MetaFlags : uint32_t {
    kHasOrientation = 1u << 0,
    kHasDate = 1u << 1,
    kOffsetKnown = 1u << 2,
    kHasGps = 1u << 3,
};

enum SpecialFormat : uint32_t {
    kSpecialNone = 0,
    kSpecialGif = 1,
    kSpecialMotionPhoto = 2,
    kSpecialAnimatedWebp = 3,
};

struct Meta {
    uint32_t magic;
    uint32_t version;  // 1
    uint32_t flags;    // MetaFlags
    uint32_t format;
    uint32_t width;
    uint32_t height;
    int32_t orientation;  // 0, 90, 180, 270, or -1
    uint32_t specialFormat;
    int64_t dateTakenMillis;  // UTC with kOffsetKnown, else the wall time read as UTC
    int32_t latitudeE7;       // degrees * 1e7
    int32_t longitudeE7;
    char description[kTextChars];
    char exposureTime[kNumberChars];
    char fNumber[kNumberChars];
    char iso[kNumberChars];
    char sceneCaptureType[kNumberChars];
    char documentId[kIdChars];
    char instanceId[kIdChars];
    char originalDocumentId[kIdChars];
    uint8_t reserved[208];
};
static_assert(sizeof(Meta) == 1024);

}  // namespace decoder
