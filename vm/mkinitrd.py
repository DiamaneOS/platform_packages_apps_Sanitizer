#!/usr/bin/env python3
#
# Copyright (C) 2026 DiamaneOS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""mkinitrd.py OUT INIT: the decoder VM's initramfs, a newc cpio with /init (INIT), /dev/console and empty /dev and
/proc. Fixed owner, times and inode numbers, so the same INIT always gives the same bytes."""

import stat
import sys


def pad(b):
    return b + b'\0' * (-len(b) % 4)


def main():
    out, init = sys.argv[1], sys.argv[2]
    with open(init, 'rb') as f:
        body = f.read()
    entries = [('dev', stat.S_IFDIR | 0o755, b'', 0, 0), ('dev/console', stat.S_IFCHR | 0o600, b'', 5, 1),
               ('proc', stat.S_IFDIR | 0o755, b'', 0, 0), ('init', stat.S_IFREG | 0o755, body, 0, 0),
               ('TRAILER!!!', 0, b'', 0, 0)]
    data = b''
    for ino, (name, mode, content, rmaj, rmin) in enumerate(entries, 1):
        nb = name.encode() + b'\0'
        nlink = 2 if stat.S_ISDIR(mode) else 1
        fields = [ino if name != 'TRAILER!!!' else 0, mode, 0, 0, nlink if mode else 1, 0, len(content), 0, 0, rmaj,
                  rmin, len(nb), 0]
        data += pad(b'070701' + ''.join('%08X' % f for f in fields).encode() + nb) + pad(content)
    data += b'\0' * (-len(data) % 512)
    with open(out, 'wb') as f:
        f.write(data)


if __name__ == '__main__':
    main()
