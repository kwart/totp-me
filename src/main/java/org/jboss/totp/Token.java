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

import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * @author Josef Cacek
 * @author Lukas Krejci
 */
public class Token {
    private final String name;
    private final int timeStep;
    private final String key;
    private final byte hmacAlgorithm;
    private final byte passCodeLength;
    private final int timeDelta;
    private final HMac hmac;

    private String currentPassCode;
    private long lastCounter;

    /**
     * Generates the current token. If the token can't be generated it returns
     * an empty String.
     *
     * @return current token or an empty String
     */
    private static String genToken(final long counter, final HMac hmac, final int digits) {
        if (hmac == null || digits <= 0) {
            return "";
        }

        // generate 8 byte HOTP counter value (RFC 4226)
        final byte msg[] = new byte[8];
        for (int i = 0; i < 8; i++) {
            msg[7 - i] = (byte) (counter >>> (i * 8));
        }

        //compute the HMAC
        final byte[] hash = new byte[hmac.getMacSize()];
        hmac.update(msg, 0, msg.length);
        hmac.doFinal(hash, 0);

        // Transform the HMAC to a HOTP value according to RFC 4226.
        final int off = hash[hash.length - 1] & 0xF;
        // Truncate the HMAC (look at RFC 4226 section 5.3, step 2).
        int binary = ((hash[off] & 0x7f) << 24) | ((hash[off + 1] & 0xff) << 16) | ((hash[off + 2] & 0xff) << 8)
            | ((hash[off + 3] & 0xff));

        // use requested number of digits
        final byte[] digitsArray = new byte[digits];
        for (int i = 0; i < digits; i++) {
            digitsArray[digits - 1 - i] = (byte) ('0' + (char) (binary % 10));
            binary /= 10;
        }
        return new String(digitsArray, 0, digits);
    }

    public static Token readFrom(DataInput in) throws IOException {
        String name = in.readUTF();
        String key = in.readUTF();
        int timeStep = in.readInt();
        byte hmacAlgorithm = in.readByte();
        byte passCodeLength = in.readByte();
        int timeDelta = in.readInt();

        return new Token(name, hmacAlgorithm, timeStep, key, passCodeLength, timeDelta);
    }

    public Token(String name, byte hmacAlgorithm, int timeStep, String key, byte passCodeLength, int timeDelta) {
        this.name = name;
        this.hmacAlgorithm = hmacAlgorithm;
        this.timeStep = timeStep;
        this.key = key;
        this.passCodeLength = passCodeLength;
        this.timeDelta = timeDelta;

        Digest digest = null;
        switch(hmacAlgorithm) {
        case HMACAlgorithm.SHA_1:
            digest = new SHA1Digest();
            break;
        case HMACAlgorithm.SHA_256:
            digest = new SHA256Digest();
            break;
        case HMACAlgorithm.SHA_512:
            digest = new SHA512Digest();
            break;
        }
        hmac = new HMac(digest);
        byte[] secret = Base32.decode(key);
        hmac.init(new KeyParameter(secret));
    }

    public void writeTo(DataOutput out) throws IOException {
        out.writeUTF(name);
        out.writeUTF(key);
        out.writeInt(timeStep);
        out.writeByte(hmacAlgorithm);
        out.writeByte(passCodeLength);
        out.writeInt(timeDelta);
    }

    public byte[] serialize() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        try {
            writeTo(dos);

            dos.flush();

            return baos.toByteArray();
        } finally {
            dos.close();
        }
    }

    public byte getHmacAlgorithm() {
        return hmacAlgorithm;
    }

    /**
     * Base32 encoded key.
     * @return
     */
    public String getKey() {
        return key;
    }

    public String getName() {
        return name;
    }

    public byte getPassCodeLength() {
        return passCodeLength;
    }

    public int getTimeDelta() {
        return timeDelta;
    }

    public int getTimeStep() {
        return timeStep;
    }

    public String getCurrentPassCode() {
        long currentCounter = getCounter();
        if (lastCounter != currentCounter) {
            currentPassCode = genToken(currentCounter, hmac, passCodeLength);
        }
        return currentPassCode;
    }

    public int getRemainingValidTime() {
        return (int) ( timeStep - (System.currentTimeMillis() / 1000 + timeDelta) % timeStep);
    }

    private long getCounter() {
        return timeStep > 0 ? System.currentTimeMillis() / 1000L / timeStep : -1;
    }
}
