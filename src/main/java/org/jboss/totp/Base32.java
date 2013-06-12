/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013, Red Hat, Inc. and/or its affiliates, and individual
 * contributors by the @authors tag. See the copyright.txt in the
 * distribution for a full listing of individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jboss.totp;

/**
 * @author Josef Cacek
 * @author Lukas Krejci
 */
public class Base32 {

    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private static final int[] BASE32_LOOKUP = { 0xFF, 0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    private static final int[] BASE32_LEN = { 0, 2, 4, 5, 7, 8 };

    private Base32() {

    }

    public static String encode(byte[] input) {
        if (input == null) {
            return "";
        }
        int i = 0, index = 0, digit = 0;
        int currByte, nextByte;
        StringBuffer base32 = new StringBuffer((input.length + 7) * 8 / 5);

        while (i < input.length) {
            currByte = (input[i] >= 0) ? input[i] : (input[i] + 256); // unsign

			/* Is the current digit going to span a byte boundary? */
            if (index > 3) {
                if ((i + 1) < input.length) {
                    nextByte = (input[i + 1] >= 0) ? input[i + 1] : (input[i + 1] + 256);
                } else {
                    nextByte = 0;
                }

                digit = currByte & (0xFF >> index);
                index = (index + 5) % 8;
                digit <<= index;
                digit |= nextByte >> (8 - index);
                i++;
            } else {
                digit = (currByte >> (8 - (index + 5))) & 0x1F;
                index = (index + 5) % 8;
                if (index == 0)
                    i++;
            }
            base32.append(BASE32_CHARS.charAt(digit));
        }

        return base32.toString();
    }

    public static byte[] decode(String input) {
        if (input == null || input.length() == 0)
            return null;
        final String base32 = input.toUpperCase();
        int i, index, lookup, offset, digit;
        byte[] bytes = new byte[base32.length() * 5 / 8];

        for (i = 0, index = 0, offset = 0; i < base32.length(); i++) {
            lookup = base32.charAt(i) - '0';

			/* Skip chars outside the lookup table */
            if (lookup < 0 || lookup >= BASE32_LOOKUP.length) {
                continue;
            }

            digit = BASE32_LOOKUP[lookup];

			/* If this digit is not in the table, ignore it */
            if (digit == 0xFF) {
                continue;
            }

            if (index <= 3) {
                index = (index + 5) % 8;
                if (index == 0) {
                    bytes[offset] |= digit;
                    offset++;
                    if (offset >= bytes.length)
                        break;
                } else {
                    bytes[offset] |= digit << (8 - index);
                }
            } else {
                index = (index + 5) % 8;
                bytes[offset] |= (digit >>> index);
                offset++;

                if (offset >= bytes.length) {
                    break;
                }
                bytes[offset] |= digit << (8 - index);
            }
        }
        return bytes;
    }

    public static String validate(String input) {
        final StringBuffer sb = new StringBuffer();
        input = input.toUpperCase().replace('0', 'O');
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if (BASE32_CHARS.indexOf(ch) >= 0) {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    public static int getEncodedLength(int rawLength) {
        return rawLength / 5 * 8 + BASE32_LEN[rawLength % 5];
    }
}
