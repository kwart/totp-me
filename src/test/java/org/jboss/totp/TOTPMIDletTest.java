package org.jboss.totp;

import junit.framework.TestCase;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * JUnit test for the TOTP generator. Based on <a
 * href="http://tools.ietf.org/html/rfc6238#appendix-B">test vectors from the
 * RFC 6238</a>.
 * 
 * @author Josef Cacek
 */
public class TOTPMIDletTest extends TestCase {

	private static final int TIMESTEP = 30;
	private static final int DIGITS = 8;

	// Seed for HMAC-SHA1 - 20 bytes
	private static final byte[] seed20 = "12345678901234567890".getBytes();
	// Seed for HMAC-SHA256 - 32 bytes
	private static final byte[] seed32 = "12345678901234567890123456789012".getBytes();
	// Seed for HMAC-SHA512 - 64 bytes
	private static final byte[] seed64 = "1234567890123456789012345678901234567890123456789012345678901234".getBytes();

	private static final long[] TEST_TIME = { 59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L };
	private static final String[] SHA1_VALUES = { "94287082", "07081804", "14050471", "89005924", "69279037",
			"65353130" };
	private static final String[] SHA256_VALUES = { "46119246", "68084774", "67062674", "91819424", "90698825",
			"77737706" };
	private static final String[] SHA512_VALUES = { "90693936", "25091201", "99943326", "93441116", "38618901",
			"47863826" };

	public void testTOTP() {
		HMac sha1Hmac = new HMac(new SHA1Digest());
		sha1Hmac.init(new KeyParameter(seed20));
		HMac sha256Hmac = new HMac(new SHA256Digest());
		sha256Hmac.init(new KeyParameter(seed32));
		HMac sha512Hmac = new HMac(new SHA512Digest());
		sha512Hmac.init(new KeyParameter(seed64));
		for (int i = 0; i < TEST_TIME.length; i++) {
			long counter = TOTPMIDlet.getCounter(TEST_TIME[i], TIMESTEP);
			assertEquals(SHA1_VALUES[i], TOTPMIDlet.genToken(counter, sha1Hmac, DIGITS));
			assertEquals(SHA256_VALUES[i], TOTPMIDlet.genToken(counter, sha256Hmac, DIGITS));
			assertEquals(SHA512_VALUES[i], TOTPMIDlet.genToken(counter, sha512Hmac, DIGITS));
		}
	}
}
