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

import javax.microedition.lcdui.Alert;
import javax.microedition.lcdui.AlertType;
import javax.microedition.lcdui.Choice;
import javax.microedition.lcdui.ChoiceGroup;
import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Display;
import javax.microedition.lcdui.Displayable;
import javax.microedition.lcdui.Form;
import javax.microedition.lcdui.Gauge;
import javax.microedition.lcdui.Item;
import javax.microedition.lcdui.StringItem;
import javax.microedition.lcdui.TextField;
import javax.microedition.midlet.MIDlet;
import javax.microedition.rms.RecordStore;
import javax.microedition.rms.RecordStoreNotFoundException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * TOTP generator for Java ME.
 * 
 * @author Josef Cacek
 */
public class TOTPMIDlet extends MIDlet implements CommandListener {

	private static final boolean DEBUG = false;

	private static final String STORE_CONFIG = "config";
	private static final String STORE_KEY = "key";

	private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	private static final int[] BASE32_LOOKUP = { 0xFF, 0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	private static final char[] HEX_TABLE = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
			'e', 'f' };

	private static final int[] BASE32_LEN = { 0, 2, 4, 5, 7, 8 };

	private static final String SHA1 = "SHA-1";
	private static final String SHA256 = "SHA-256";
	private static final String SHA512 = "SHA-512";

	private static final String[] HMAC_ALGORITHMS = { SHA1, SHA256, SHA512 };
	private static final int[] HMAC_BYTE_COUNT = { 160 / 8, 256 / 8, 512 / 8 };

	private static final int DEFAULT_TIMESTEP = 30;
	private static final byte[] DEFAULT_SECRET = null;
	private static final int DEFAULT_DIGITS = 6;
	private static final int DEFAULT_HMAC_ALG_IDX = 0;

	// GUI components
	private Command cmdOK = new Command("OK", Command.OK, 1);
	private Command cmdGeneratorOK = new Command("OK", Command.OK, 1);
	private Command cmdOptions = new Command("Options", Command.SCREEN, 1);
	private Command cmdExit = new Command("Exit", Command.CANCEL, 1);
	private Command cmdGenerator = new Command("Key generator", Command.SCREEN, 2);
	private Command cmdNewKey = new Command("New key", Command.SCREEN, 1);
	private Command cmdReset = new Command("Default values", Command.SCREEN, 3);

	private final StringItem siKeyHex = new StringItem("HEX", null);
	private final StringItem siKeyBase32 = new StringItem("Base32", null);
	private final StringItem siToken = new StringItem("Token", null);
	private final Gauge validity = new Gauge (null, false, DEFAULT_TIMESTEP, DEFAULT_TIMESTEP);
	private final TextField tfSecret = new TextField("Secret key (Base32)", null, 105, TextField.ANY);
	private final TextField tfTimeStep = new TextField("Time step (sec)", null, 3, TextField.NUMERIC);
	private final TextField tfDigits = new TextField("Number of digits", null, 2, TextField.NUMERIC);
	private final ChoiceGroup chgHmacAlgorithm = new ChoiceGroup("HMAC algorithm", Choice.EXCLUSIVE);

	private final Alert alInvalid = new Alert("Warning", "Invalid input!", null, AlertType.ALARM);

	private final Form fMain = new Form("TOTP");
	private final Form fOptions = new Form("TOTP configuration");
	private final Form fGenerator = new Form("Key generator");

	private final Timer timer = new Timer();
	private final RefreshPinTask refreshPinTask = new RefreshPinTask();

	private HMac hmac;
	private final Random rand = new Random();
	private int period;
	
    // Constructors ----------------------------------------------------------

	public TOTPMIDlet() {

		// Main display
		fMain.append(siToken);
		fMain.append(validity);
		fMain.addCommand(cmdExit);
		fMain.addCommand(cmdOptions);
		fMain.addCommand(cmdGenerator);
		fMain.setCommandListener(this);
		
		validity.setLayout(validity.getLayout() | Item.LAYOUT_CENTER);
		
		// Key generator
		fGenerator.append(siKeyHex);
		fGenerator.append(siKeyBase32);
		fGenerator.addCommand(cmdGeneratorOK);
		fGenerator.addCommand(cmdNewKey);
		fGenerator.setCommandListener(this);

		// Configuration display
		fOptions.append(tfSecret);
		fOptions.append(tfTimeStep);
		fOptions.append(tfDigits);
		for (int i = 0; i < HMAC_ALGORITHMS.length; i++) {
			chgHmacAlgorithm.append(HMAC_ALGORITHMS[i], null);
		}
		fOptions.append(chgHmacAlgorithm);
		fOptions.addCommand(cmdOK);
		fOptions.addCommand(cmdGenerator);
		fOptions.addCommand(cmdReset);
		fOptions.setCommandListener(this);

		// set alert
		alInvalid.setTimeout(Alert.FOREVER);

		tfTimeStep.setString(String.valueOf(DEFAULT_TIMESTEP));
		tfDigits.setString(String.valueOf(DEFAULT_DIGITS));
		chgHmacAlgorithm.setSelectedIndex(DEFAULT_HMAC_ALG_IDX, true);

	}

	// Public methods --------------------------------------------------------

	public void startApp() {
		try {
			load();
			final Display display = Display.getDisplay(this);
			final String secret = tfSecret.getString();
			if (secret == null || secret.length() == 0) {
				display.setCurrent(fOptions);
			} else {
				// use validation - to check loaded data
				commandAction(cmdOK, null);
			}
			validity.setMaxValue(period);
			timer.schedule(refreshPinTask, 0L, 1000L);

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
		final Display display = Display.getDisplay(this);
		if (aCmd == cmdOK) {
			final String warning = validateInput();
			if (warning.length() == 0) {
				final int algorithmIdx = chgHmacAlgorithm.getSelectedIndex();
				final byte[] secretKey = base32Decode(tfSecret.getString());
				HMac newHmac = null;
				if (secretKey != null) {
					Digest digest = null;
					if (SHA1.equals(HMAC_ALGORITHMS[algorithmIdx])) {
						digest = new SHA1Digest();
					} else if (SHA256.equals(HMAC_ALGORITHMS[algorithmIdx])) {
						digest = new SHA256Digest();
					} else if (SHA512.equals(HMAC_ALGORITHMS[algorithmIdx])) {
						digest = new SHA512Digest();
					}
					newHmac = new HMac(digest);
					newHmac.init(new KeyParameter(secretKey));
				}
				setHMac(newHmac);
				refreshPinTask.run();
				display.setCurrent(fMain);
			} else {
				alInvalid.setString("Invalid input:\n" + warning);
				display.setCurrent(alInvalid, fOptions);
			}
		} else if (aCmd == cmdGenerator) {
			final byte[] key = base32Decode(tfSecret.getString());
			//set current key
			siKeyHex.setText(key == null ? "" : toHexString(key, 0, key.length));
			siKeyBase32.setText(base32Encode(key));
			display.setCurrent(fGenerator);
		} else if (aCmd == cmdNewKey) {
			final byte[] secretKey = generateNewKey();
			siKeyHex.setText(toHexString(secretKey, 0, secretKey.length));
			siKeyBase32.setText(base32Encode(secretKey));
			tfSecret.setString(siKeyBase32.getText());
		} else if (aCmd == cmdGeneratorOK) {
			display.setCurrent(fOptions);
		} else if (aCmd == cmdOptions) {
			display.setCurrent(fOptions);
		} else if (aCmd == cmdReset) {
			tfSecret.setString(base32Encode(DEFAULT_SECRET));
			tfTimeStep.setString(Integer.toString(DEFAULT_TIMESTEP));
			tfDigits.setString(Integer.toString(DEFAULT_DIGITS));
			chgHmacAlgorithm.setSelectedIndex(DEFAULT_HMAC_ALG_IDX, true);
		} else if (aCmd == cmdExit) {
			destroyApp(false);
		}
	}

	// Private methods -------------------------------------------------------

	private synchronized HMac getHMac() {
		return hmac;
	}

	private synchronized void setHMac(HMac hmac) {
		this.hmac = hmac;
	}

	/**
	 * Validates (and makes basic corrections in) the options form. It returns
	 * warning message(s) if the validation error occures. An empty string is
	 * returned if the validation is successful.
	 * 
	 * @return warning message
	 */
	private String validateInput() {
		final StringBuffer warnings = new StringBuffer();

		int algIdx = chgHmacAlgorithm.getSelectedIndex();
		if (algIdx < 0) {
			algIdx = 0;
			chgHmacAlgorithm.setSelectedIndex(algIdx, true);
		}

		String str = tfSecret.getString();
		if (str == null) {
			str = "";
		} else {
			final StringBuffer sb = new StringBuffer();
			str = str.toUpperCase().replace('0', 'O');
			for (int i = 0; i < str.length(); i++) {
				char ch = str.charAt(i);
				if (BASE32_CHARS.indexOf(ch) >= 0) {
					sb.append(ch);
				}
			}
			str = sb.toString();
		}
		tfSecret.setString(str);
		final int keyLen = str.length();
		int expectedBase32Len = getBase32Len(HMAC_BYTE_COUNT[algIdx]);
		if (keyLen != 0 && keyLen != expectedBase32Len) {
			warnings.append("Base32 encoded key for ").append(HMAC_ALGORITHMS[algIdx]).append(" must have ")
					.append(expectedBase32Len).append(" characters.");
		}

		int step = 0;
		try {
			step = Integer.parseInt(tfTimeStep.getString());
		} catch (NumberFormatException e) {
			tfTimeStep.setString(Integer.toString(DEFAULT_TIMESTEP));
			step = DEFAULT_TIMESTEP;
		}
		if (step <= 0) {
			if (warnings.length() > 0)
				warnings.append("\n");
			warnings.append("Time step must be positive number.");
		}
		period = step;
		
		int digits = 0;
		try {
			digits = Integer.parseInt(tfDigits.getString());
		} catch (NumberFormatException e) {
			tfDigits.setString(Integer.toString(DEFAULT_DIGITS));
		}
		if (digits <= 0) {
			if (warnings.length() > 0)
				warnings.append("\n");
			warnings.append("Number of digits must be positive number.");
		}

		return warnings.toString();
	}

	/**
	 * Loads configuration from the record stores. It doesn't update the GUI,
	 * but only the parameters.
	 * 
	 * @throws Exception
	 */
	private void load() throws Exception {
		RecordStore tmpRS = null;

		try {
			tmpRS = RecordStore.openRecordStore(STORE_KEY, false);

			if ((tmpRS != null) && (tmpRS.getNumRecords() > 0)) {
				tfSecret.setString(base32Encode(tmpRS.getRecord(1)));
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
		} catch (Exception e) {
			if (tmpRS != null) {
				tmpRS.closeRecordStore();
				RecordStore.deleteRecordStore(STORE_CONFIG);
			}
		}
	}

	/**
	 * Saves key and configuration.
	 * 
	 * @throws Exception
	 */
	private void save() throws Exception {
		RecordStore tmpRS = null;

		try {
			final byte[] key = base32Decode(tfSecret.getString());
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

	/**
	 * Loads configuration from given DataInput
	 * 
	 * @param aDis
	 * @throws Exception
	 */
	private void loadConfig(DataInput aDis) throws Exception {
		tfTimeStep.setString(String.valueOf(aDis.readInt()));
		chgHmacAlgorithm.setSelectedIndex(aDis.readInt(), true);
		tfDigits.setString(String.valueOf(aDis.readByte()));
	}

	private void saveConfig(DataOutput aDos) throws Exception {
		aDos.writeInt(Integer.parseInt(tfTimeStep.getString()));
		aDos.writeInt(chgHmacAlgorithm.getSelectedIndex());
		aDos.writeByte(Integer.parseInt(tfDigits.getString()));
	}

	/**
	 * Generates the current PIN.
	 */
	private String genToken() {
		final HMac hmac = getHMac();
		int timeStep = -1;
		int digits = -1;
		try {
			timeStep = Integer.parseInt(tfTimeStep.getString());
			digits = Integer.parseInt(tfDigits.getString());
		} catch (NumberFormatException e) {
			debugErr(e.getMessage());
		}

		if (hmac == null || timeStep <= 0 || digits <= 0) {
			return "";
		}

		// generate 8 byte HOTP counter value (RFC 4226)
		final byte msg[] = new byte[8];
		// time steps since the Epoch
		final long counter = (new Date()).getTime() / (1000L * timeStep);
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
			base32.append(BASE32_CHARS.charAt(digit));
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
			return null;
		final String base32 = aBase32.toUpperCase();
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

	/**
	 * Convert a byte array to a String with a hexidecimal format.
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
	private static String toHexString(byte[] data, int offset, int length) {
		if (data == null || data.length == 0)
			return "";

		final StringBuffer s = new StringBuffer(length * 2);
		for (int i = offset; i < offset + length; i++) {
			s.append(HEX_TABLE[(data[i] & 0xf0) >>> 4]);
			s.append(HEX_TABLE[(data[i] & 0x0f)]);
		}
		return s.toString();
	}

	private byte[] generateNewKey() {
		byte[] result = new byte[HMAC_BYTE_COUNT[chgHmacAlgorithm.getSelectedIndex()]];
		for (int i = 0, len = result.length; i < len;)
			for (int rnd = rand.nextInt(), n = Math.min(len - i, 4); n-- > 0; rnd >>= 8)
				result[i++] = (byte) rnd;
		return result;
	}

	private static int getBase32Len(int byteCount) {
		return byteCount / 5 * 8 + BASE32_LEN[byteCount % 5];
	}

	// Embedded classes ------------------------------------------------------

	/**
	 * Task for refreshing the PIN.
	 */
	private class RefreshPinTask extends TimerTask {

		private int counter;

		public final void run() {
			if (counter-- > 0) {
				validity.setValue(validity.getValue() - 1);
			} else {
				final String newToken = genToken();
				debug(newToken);
				siToken.setText(newToken);
				counter = period;
				validity.setValue(period);
			}
		}
	}
}
