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
 * What the decode service takes from its application: the decoder, the permission callers need and the packages
 * allowed to call. The product's {@link DecoderApp} fixes all three. A test build's application supplies its own,
 * so the self-test can go through the real binder service.
 */
interface DecoderProvider {
    Decoder decoder();

    String callerPermission();

    /** Packages that may call, besides the system server (uid 1000). */
    String[] allowedCallers();
}
