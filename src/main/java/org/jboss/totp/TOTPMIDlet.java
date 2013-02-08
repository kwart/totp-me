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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.util.Date;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;

import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Display;
import javax.microedition.lcdui.Displayable;
import javax.microedition.lcdui.Form;
import javax.microedition.lcdui.StringItem;
import javax.microedition.lcdui.TextField;
import javax.microedition.midlet.MIDlet;
import javax.microedition.rms.RecordStore;
import javax.microedition.rms.RecordStoreNotFoundException;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * TOTP generator based on <a
 * href="http://code.google.com/p/gauthj2me/">gauthj2me</a> project (which
 * didn't work on my Siemens S75 phone).
 * 
 * @author Josef Cacek
 */
public class TOTPMIDlet extends MIDlet implements CommandListener {

	private final static int DIGITS = 6;

	private static final boolean DEBUG = false;

	private static final String STORE_CONFIG = "config";
	private static final String STORE_KEY = "key";

	private static final String base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	private static final int[] base32Lookup = { 0xFF, 0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
			0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	private static char[] hex_table = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	private byte[] secretKey;
	private int timeStep = 30;

	private Command cmdOK = new Command("OK", Command.OK, 1);
	private Command cmdGeneratorOK = new Command("OK", Command.OK, 1);
	private Command cmdCancel = new Command("Cancel", Command.CANCEL, 1);
	private Command cmdOptions = new Command("Options", Command.SCREEN, 1);
	private Command cmdExit = new Command("Exit", Command.CANCEL, 1);
	private Command cmdGenerator = new Command("Key generator", Command.SCREEN, 2);
	private Command cmdNewKey = new Command("New key", Command.SCREEN, 1);

	private final StringItem siKeyHex = new StringItem("HEX:", null);
	private final StringItem siKeyBase32 = new StringItem("Base32:", null);
	private final StringItem siPin = new StringItem("PIN:", null);
	private final TextField tfSecret = new TextField("Secret key (Base32):", null, 64, TextField.ANY);
	private final TextField tfTimeStep = new TextField("Time step (sec):", null, 3, TextField.NUMERIC);

	private final MainForm fMain = new MainForm();
	private final OptionsForm fOptions = new OptionsForm();
	private final GeneratorForm fGenerator = new GeneratorForm();

	private final Timer timer = new Timer();
	private final RefreshPinTask refreshPinTask = new RefreshPinTask();

	// Public methods --------------------------------------------------------

	public void startApp() {
		try {
			load();
			timer.schedule(refreshPinTask, 0L, 1000L);
			tfTimeStep.setString(Integer.toString(timeStep));
			if (getSecretKey() == null) {
				Display.getDisplay(this).setCurrent(fOptions);
			} else {
				tfSecret.setString(base32Encode(secretKey));
				Display.getDisplay(this).setCurrent(fMain);
			}
		} catch (Exception e) {
			debugErr("TOTPMIDlet.startApp() - " + e.getMessage());
			error(e);
		}
	}

	public void pauseApp() {
	}

	public void destroyApp(boolean unconditional) {
		try {
			save();
		} catch (Exception e) {
			debugErr("Saving config in destroyApp failed: " + e.getMessage());
			error(e);
		}
		refreshPinTask.cancel();
		timer.cancel();
		notifyDestroyed();
	}

	public void commandAction(Command aCmd, Displayable aDisp) {
		debug("Options - Command action " + aCmd);
		if (aCmd == cmdCancel) {
			final String base32Encode = base32Encode(getSecretKey());
			tfSecret.setString(base32Encode != null ? base32Encode : "");
			tfTimeStep.setString(Integer.toString(timeStep));
			Display.getDisplay(this).setCurrent(fMain);
		} else if (aCmd == cmdOK) {
			setSecretKey(base32Decode(tfSecret.getString()));
			timeStep = Integer.parseInt(tfTimeStep.getString());
			refreshPinTask.run();
			Display.getDisplay(this).setCurrent(fMain);
		} else if (aCmd == cmdGenerator) {
			byte[] key = getSecretKey();
			//just in case we're comming from OptionsForm
			timeStep = Integer.parseInt(tfTimeStep.getString());
			//set current key
			siKeyHex.setText(key == null ? "" : toHexString(key, 0, key.length));
			siKeyBase32.setText(base32Encode(key));
			Display.getDisplay(this).setCurrent(fGenerator);
		} else if (aCmd == cmdNewKey) {
			byte[] newKey = generateNewKey();
			setSecretKey(newKey);
			siKeyHex.setText(toHexString(newKey, 0, newKey.length));
			siKeyBase32.setText(base32Encode(newKey));
			tfSecret.setString(siKeyBase32.getText());
		} else if (aCmd == cmdGeneratorOK) {
			Display.getDisplay(this).setCurrent(fMain);
		} else if (aCmd == cmdOptions) {
			Display.getDisplay(this).setCurrent(fOptions);
		} else if (aCmd == cmdExit) {
			destroyApp(false);
		}
	}

	// Private methods -------------------------------------------------------

	private synchronized byte[] getSecretKey() {
		return secretKey;
	}

	private synchronized void setSecretKey(byte[] secretKey) {
		this.secretKey = secretKey;
	}

	private void load() throws Exception {
		RecordStore tmpRS = null;

		try {
			tmpRS = RecordStore.openRecordStore(STORE_KEY, false);

			if ((tmpRS != null) && (tmpRS.getNumRecords() > 0)) {
				setSecretKey(tmpRS.getRecord(1));
			}
		} catch (RecordStoreNotFoundException e) {
			debug(e.getMessage());
		} finally {
			if (tmpRS != null) {
				tmpRS.closeRecordStore();
			}
		}

		try {
			tmpRS = RecordStore.openRecordStore(STORE_CONFIG, false);

			if ((tmpRS != null) && (tmpRS.getNumRecords() > 0)) {
				byte[] bytes = tmpRS.getRecord(1);
				ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
				DataInputStream dis = new DataInputStream(bais);
				loadConfig(dis);
				dis.close();
			}
		} catch (RecordStoreNotFoundException e) {
			debug(e.getMessage());
		} finally {
			if (tmpRS != null) {
				tmpRS.closeRecordStore();
			}
		}
	}

	/**
	 * Loads configuration from given DataInput
	 * 
	 * @param aDis
	 * @throws Exception
	 */
	private void loadConfig(DataInput aDis) throws Exception {
		timeStep = aDis.readInt();
	}

	/**
	 * Saves key and configuration.
	 * 
	 * @throws Exception
	 */
	private void save() throws Exception {
		RecordStore tmpRS = null;

		try {
			final byte[] key = getSecretKey();
			if (key == null) {
				RecordStore.deleteRecordStore(STORE_KEY);
			} else {
				tmpRS = RecordStore.openRecordStore(STORE_KEY, true);
				if (tmpRS.getNumRecords() == 0) {
					tmpRS.addRecord(key, 0, key.length);
				} else {
					tmpRS.setRecord(1, key, 0, key.length);
				}
			}
		} finally {
			if (tmpRS != null) {
				tmpRS.closeRecordStore();
			}
		}

		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DataOutputStream dos = new DataOutputStream(baos);
			saveConfig(dos);
			dos.flush();

			byte[] bytes = baos.toByteArray();
			tmpRS = RecordStore.openRecordStore(STORE_CONFIG, true);

			if (tmpRS.getNumRecords() == 0) {
				tmpRS.addRecord(bytes, 0, bytes.length);
			} else {
				tmpRS.setRecord(1, bytes, 0, bytes.length);
			}

			dos.close();
		} finally {
			if (tmpRS != null) {
				tmpRS.closeRecordStore();
			}
		}
	}

	private void saveConfig(DataOutput aDos) throws Exception {
		aDos.writeInt(timeStep);
	}

	/**
	 * Generates the current PIN.
	 */
	private String genToken() {
		final byte[] key = getSecretKey();
		if (key == null) {
			return "";
		}
		final byte msg[] = new byte[8];
		final long counter = (new Date()).getTime() / (1000L * timeStep);
		for (int i = 0; i < 8; i++) {
			msg[7 - i] = (byte) (counter >>> (i * 8));
		}

		final HMac hmac = new HMac(new SHA1Digest());
		final byte[] hash = new byte[hmac.getMacSize()];
		hmac.init(new KeyParameter(key));
		hmac.update(msg, 0, msg.length);
		hmac.doFinal(hash, 0);

		final int off = hash[hash.length - 1] & 0xF;
		int binary = ((hash[off] & 0x7f) << 24) | ((hash[off + 1] & 0xff) << 16) | ((hash[off + 2] & 0xff) << 8)
				| ((hash[off + 3] & 0xff));

		for (int i = 0; i < DIGITS; i++) {
			msg[DIGITS - 1 - i] = (byte) ('0' + (char) (binary % 10));
			binary /= 10;
		}
		return new String(msg, 0, DIGITS);
	}

	/**
	 * Debug function
	 * 
	 * @param aWhat
	 */
	public synchronized static void debug(final String aWhat) {
		if (DEBUG) {
			System.out.println(">>>DEBUG " + aWhat);
		}
	}

	/**
	 * Debug function for errors
	 * 
	 * @param aWhat
	 */
	public synchronized static void debugErr(final String aWhat) {
		if (DEBUG) {
			System.err.println(">>>ERROR " + aWhat);
		}
	}

	/**
	 * Prints error.
	 * 
	 * @param anErr
	 */
	private static void error(final Object anErr) {
		if (anErr instanceof Throwable) {
			((Throwable) anErr).printStackTrace();
		} else {
			System.err.println(">>>ERROR " + anErr);
		}
	}

	/**
	 * Encodes byte array to Base32 String.
	 * 
	 * @param bytes
	 *            Bytes to encode.
	 * @return Encoded byte array <code>bytes</code> as a String.
	 * 
	 */
	private static String base32Encode(final byte[] bytes) {
		if (bytes == null) {
			return "";
		}
		int i = 0, index = 0, digit = 0;
		int currByte, nextByte;
		StringBuffer base32 = new StringBuffer((bytes.length + 7) * 8 / 5);

		while (i < bytes.length) {
			currByte = (bytes[i] >= 0) ? bytes[i] : (bytes[i] + 256); // unsign

			/* Is the current digit going to span a byte boundary? */
			if (index > 3) {
				if ((i + 1) < bytes.length) {
					nextByte = (bytes[i + 1] >= 0) ? bytes[i + 1] : (bytes[i + 1] + 256);
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
			base32.append(base32Chars.charAt(digit));
		}

		return base32.toString();
	}

	/**
	 * Decodes the given Base32 String to a raw byte array.
	 * 
	 * @param base32
	 * @return Decoded <code>base32</code> String as a raw byte array.
	 */
	private static byte[] base32Decode(final String aBase32) {
		if (aBase32 == null || aBase32.length() == 0)
			return new byte[0];
		final String base32 = aBase32.toUpperCase();
		int i, index, lookup, offset, digit;
		byte[] bytes = new byte[base32.length() * 5 / 8];

		for (i = 0, index = 0, offset = 0; i < base32.length(); i++) {
			lookup = base32.charAt(i) - '0';

			/* Skip chars outside the lookup table */
			if (lookup < 0 || lookup >= base32Lookup.length) {
				continue;
			}

			digit = base32Lookup[lookup];

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

	/**
	 * Convert a byte array to a String with a hexidecimal format. The String
	 * may be converted back to a byte array using fromHexString. <BR>
	 * For each byte (b) two characaters are generated, the first character
	 * represents the high nibble (4 bits) in hexidecimal (<code>b & 0xf0</code>
	 * ), the second character represents the low nibble (<code>b & 0x0f</code>
	 * ). <BR>
	 * The byte at <code>data[offset]</code> is represented by the first two
	 * characters in the returned String.
	 * 
	 * @param data
	 *            byte array
	 * @param offset
	 *            starting byte (zero based) to convert.
	 * @param length
	 *            number of bytes to convert.
	 * 
	 * @return the String (with hexidecimal format) form of the byte array
	 */
	public static String toHexString(byte[] data, int offset, int length) {
		if (data == null || data.length == 0)
			return "";

		final StringBuffer s = new StringBuffer(length * 2);
		int end = offset + length;

		for (int i = offset; i < end; i++) {
			int high_nibble = (data[i] & 0xf0) >>> 4;
			int low_nibble = (data[i] & 0x0f);
			s.append(hex_table[high_nibble]);
			s.append(hex_table[low_nibble]);
		}

		return s.toString();
	}

	private byte[] generateNewKey() {
		byte[] result = new byte[20];
		Random rand = new Random();
		for (int i = 0, len = result.length; i < len;)
			for (int rnd = rand.nextInt(), n = Math.min(len - i, 4); n-- > 0; rnd >>= 8)
				result[i++] = (byte) rnd;
		return result;
	}

	// Embedded classes ------------------------------------------------------

	/**
	 * Configuration display.
	 */
	private class OptionsForm extends Form {

		public OptionsForm() {
			super("TOTP configuration");
			append(tfSecret);
			append(tfTimeStep);
			addCommand(cmdOK);
			addCommand(cmdCancel);
			addCommand(cmdGenerator);
			setCommandListener(TOTPMIDlet.this);
		}
	}

	/**
	 * Main display.
	 */
	private class MainForm extends Form {

		public MainForm() {
			super("TOTP");
			append(siPin);
			addCommand(cmdExit);
			addCommand(cmdOptions);
			addCommand(cmdGenerator);
			setCommandListener(TOTPMIDlet.this);
		}

	}

	private class GeneratorForm extends Form {

		public GeneratorForm() {
			super("Key generator");
			append(siKeyHex);
			append(siKeyBase32);
			addCommand(cmdGeneratorOK);
			addCommand(cmdNewKey);
			setCommandListener(TOTPMIDlet.this);
		}

	}

	/**
	 * Task for refreshing the PIN.
	 */
	private class RefreshPinTask extends TimerTask {

		public final void run() {
			final String newToken = genToken();
			debug(newToken);
			siPin.setText(newToken);
		}
	}
}
