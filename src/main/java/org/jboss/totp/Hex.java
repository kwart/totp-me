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
public class Hex {

    private static final char[] HEX_TABLE = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
        'e', 'f' };

    private Hex() {

    }

    /**
     * Convert a byte array to a String with a hexadecimal format.
     *
     * @param data
     *            byte array
     * @param offset
     *            starting byte (zero based) to convert.
     * @param length
     *            number of bytes to convert.
     *
     * @return the String (with hexadecimal format) form of the byte array
     */
    public static String toHexString(byte[] data, int offset, int length) {
        if (data == null || data.length == 0)
            return "";

        final StringBuffer s = new StringBuffer(length * 2);
        for (int i = offset; i < offset + length; i++) {
            s.append(HEX_TABLE[(data[i] & 0xf0) >>> 4]);
            s.append(HEX_TABLE[(data[i] & 0x0f)]);
        }
        return s.toString();
    }
}
