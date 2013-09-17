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
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Calendar;
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
import javax.microedition.lcdui.List;
import javax.microedition.lcdui.StringItem;
import javax.microedition.lcdui.TextField;
import javax.microedition.midlet.MIDlet;
import javax.microedition.rms.RecordEnumeration;
import javax.microedition.rms.RecordStore;
import javax.microedition.rms.RecordStoreException;
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

	private static final String STORE_CONFIG_OLD = "config";
	private static final String STORE_PROFILE_CONFIG = "profile-config";
	private static final String STORE_KEY_OLD = "key";

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
	private static final int DEFAULT_DELTA = 0;
	private static final int DEFAULT_HMAC_ALG_IDX = 0;

	private static final String DEFAULT_PROFILE = "Default";

	private static final long INVALID_COUNTER = -1L;

	private static final int DAY_IN_SEC = 60 * 60 * 24;

	private static final int INDEFINITE = 1;
	private static final int IDLE = 0;

	private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
	private static final byte[] DEFAULT_CONFIG_BYTES = getProfileConfig(DEFAULT_PROFILE, EMPTY_BYTE_ARRAY,
			DEFAULT_TIMESTEP, DEFAULT_HMAC_ALG_IDX, DEFAULT_DIGITS, DEFAULT_DELTA);

	// GUI components
	// main screen
	private Command cmdExit = new Command("Exit", Command.EXIT, 1);
	private Command cmdProfiles = new Command("Profiles", Command.SCREEN, 2);
	private Command cmdOptions = new Command("Options", Command.SCREEN, 3);
	// main+options screen
	private Command cmdGenerator = new Command("Key generator", Command.SCREEN, 4);
	// options screen
	private Command cmdOK = new Command("OK", Command.OK, 1);
	private Command cmdReset = new Command("Default values", Command.SCREEN, 3);
	// keyGenerator screen
	private Command cmdNewKey = new Command("New key", Command.SCREEN, 1);
	private Command cmdGeneratorOK = new Command("OK", Command.OK, 1);
	// profiles screen
	private Command cmdAddProfile = new Command("Add", Command.SCREEN, 1);
	private Command cmdRemoveProfile = new Command("Remove", Command.SCREEN, 2);

	private final StringItem siKeyHex = new StringItem("HEX", null);
	private final StringItem siKeyBase32 = new StringItem("Base32", null);
	private final StringItem siToken = new StringItem("Token", null);
	private final StringItem siProfile = new StringItem(null, null);
	private final Gauge gauValidity = new Gauge(null, false, DEFAULT_TIMESTEP - 1, DEFAULT_TIMESTEP);
	private final TextField tfSecret = new TextField("Secret key (Base32)", null, 105, TextField.ANY);
	private final TextField tfProfile = new TextField("Profile name", null, 105, TextField.ANY);
	private final TextField tfTimeStep = new TextField("Time step (sec)", String.valueOf(DEFAULT_TIMESTEP), 3,
			TextField.NUMERIC);
	private final TextField tfDigits = new TextField("Number of digits", String.valueOf(DEFAULT_DIGITS), 2,
			TextField.NUMERIC);
	private final TextField tfDelta = new TextField("Time correction (sec)", String.valueOf(DEFAULT_DELTA), 6,
			TextField.NUMERIC);
	private final ChoiceGroup chgHmacAlgorithm = new ChoiceGroup("HMAC algorithm", Choice.EXCLUSIVE);

	private final Alert alertWarn = new Alert("Warning", "Something went wrong!", null, AlertType.ALARM);

	private final Form fMain = new Form("TOTP ME ${project.version}");
	private final Form fOptions = new Form("TOTP configuration");
	private final Form fGenerator = new Form("Key generator");
	private final List listProfiles = new List("Profiles", Choice.IMPLICIT);

	private final Timer timer = new Timer();
	private final RefreshTokenTask refreshTokenTask = new RefreshTokenTask();

	private long cachedCounter;
	private HMac hmac;
	private final Random rand = new Random();

	private int[] recordIds;

	// Constructors ----------------------------------------------------------

	/**
	 * Constructor - initializes GUI components.
	 */
	public TOTPMIDlet() {

		// Main display
		fMain.append(siToken);
		fMain.append(gauValidity);
		fMain.append(siProfile);
		fMain.addCommand(cmdExit);
		fMain.addCommand(cmdProfiles);
		fMain.addCommand(cmdOptions);
		fMain.addCommand(cmdGenerator);
		fMain.setCommandListener(this);

		// Key generator
		fGenerator.append(siKeyHex);
		fGenerator.append(siKeyBase32);
		fGenerator.addCommand(cmdGeneratorOK);
		fGenerator.addCommand(cmdNewKey);
		fGenerator.setCommandListener(this);

		// Configuration display
		fOptions.append(tfSecret);
		fOptions.append(tfProfile);
		fOptions.append(tfTimeStep);
		fOptions.append(tfDigits);
		for (int i = 0; i < HMAC_ALGORITHMS.length; i++) {
			chgHmacAlgorithm.append(HMAC_ALGORITHMS[i], null);
		}
		fOptions.append(chgHmacAlgorithm);
		fOptions.append(tfDelta);
		fOptions.addCommand(cmdOK);
		fOptions.addCommand(cmdGenerator);
		fOptions.addCommand(cmdReset);
		fOptions.setCommandListener(this);

		// Profiles
		listProfiles.addCommand(cmdAddProfile);
		listProfiles.addCommand(cmdRemoveProfile);
		listProfiles.setCommandListener(this);

		// set alert
		alertWarn.setTimeout(Alert.FOREVER);

		tfTimeStep.setString(String.valueOf(DEFAULT_TIMESTEP));
		tfDigits.setString(String.valueOf(DEFAULT_DIGITS));
		chgHmacAlgorithm.setSelectedIndex(DEFAULT_HMAC_ALG_IDX, true);
	}

	// Public methods --------------------------------------------------------

	/**
	 * Loads configuration and initializes token-refreshing timer.
	 * 
	 * @see javax.microedition.midlet.MIDlet#startApp()
	 */
	public void startApp() {
		try {
			loadProfiles();
			if (listProfiles.size() > 1) {
				Display.getDisplay(this).setCurrent(listProfiles);
			} else {
				loadSelectedProfile();
			}
			timer.schedule(refreshTokenTask, 0L, 1000L);
		} catch (Exception e) {
			debugErr("TOTPMIDlet.startApp() - " + e.getMessage());
			error(e);
		}
	}

	/* (non-Javadoc)
	 * @see javax.microedition.midlet.MIDlet#pauseApp()
	 */
	public void pauseApp() {
	}

	/**
	 * Saves configuration to the record store and exits the refreshing timer.
	 * 
	 * @see javax.microedition.midlet.MIDlet#destroyApp(boolean)
	 */
	public void destroyApp(boolean unconditional) {
		refreshTokenTask.cancel();
		timer.cancel();
		notifyDestroyed();
	}

	/**
	 * Handles command actions from all forms.
	 * 
	 * @see javax.microedition.lcdui.CommandListener#commandAction(javax.microedition.lcdui.Command,
	 *      javax.microedition.lcdui.Displayable)
	 */
	public void commandAction(Command aCmd, Displayable aDisp) {
		if (DEBUG && aCmd != null) {
			debug("Options - Command action: " + aCmd.getLabel());
		}
		final Display display = Display.getDisplay(this);
		if (aCmd == cmdOK) {
			final String warning = validateInput();
			if (warning.length() == 0) {
				siProfile.setText(tfProfile.getString());
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
				refreshTokenTask.run();
				display.setCurrent(fMain);
				if (aDisp != null)
					save();
			} else {
				displayAlert("Invalid input:\n" + warning, fOptions);
			}
		} else if (aCmd == cmdGenerator) {
			final byte[] key = base32Decode(tfSecret.getString());
			//set current key
			siKeyHex.setText(key == null ? "" : toHexString(key, 0, key.length));
			siKeyBase32.setText(base32Encode(key));
			display.setCurrent(fGenerator);
		} else if (aCmd == cmdProfiles) {
			display.setCurrent(listProfiles);
		} else if (aCmd == cmdAddProfile) {
			final Calendar cal = Calendar.getInstance();
			// use date-time as generated profile name YYYYMMDD-HHMMSS
			final String profileName = cal.get(Calendar.YEAR) + zeroLeftPad(cal.get(Calendar.MONTH) + 1, 2)
					+ zeroLeftPad(cal.get(Calendar.DAY_OF_MONTH), 2) + "-"
					+ zeroLeftPad(cal.get(Calendar.HOUR_OF_DAY), 2) + zeroLeftPad(cal.get(Calendar.MINUTE), 2)
					+ zeroLeftPad(cal.get(Calendar.SECOND), 2);
			if (DEBUG)
				debug("Creating profile" + profileName);
			listProfiles.append(profileName, null);
			listProfiles.setSelectedIndex(listProfiles.size() - 1, true);
			int[] newRecIds = new int[recordIds.length + 1];
			System.arraycopy(recordIds, 0, newRecIds, 0, recordIds.length);
			recordIds = newRecIds;
			final byte[] profileConfig = getProfileConfig(profileName, EMPTY_BYTE_ARRAY, DEFAULT_TIMESTEP,
					DEFAULT_HMAC_ALG_IDX, DEFAULT_DIGITS, DEFAULT_DELTA);
			recordIds[recordIds.length - 1] = addProfileToRecordStore(profileConfig);
		} else if (aDisp == listProfiles && aCmd == List.SELECT_COMMAND) {
			if (listProfiles.getSelectedIndex() >= 0)
				loadSelectedProfile();
		} else if (aCmd == cmdRemoveProfile) {
			switch (listProfiles.size()) {
			case 0:
				displayAlert("There is no profile to delete.", listProfiles);
				break;
			case 1:
				displayAlert("You can't remove the last profile.", listProfiles);
				break;
			default:
				removeProfile(listProfiles.getSelectedIndex());
				break;
			}
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
			setHMac(null);
			gauValidity.setMaxValue(INDEFINITE);
			gauValidity.setValue(IDLE);
			tfSecret.setString(base32Encode(DEFAULT_SECRET));
			tfTimeStep.setString(Integer.toString(DEFAULT_TIMESTEP));
			tfDigits.setString(Integer.toString(DEFAULT_DIGITS));
			chgHmacAlgorithm.setSelectedIndex(DEFAULT_HMAC_ALG_IDX, true);
			tfDelta.setString(Integer.toString(DEFAULT_DELTA));
			tfProfile.setString(listProfiles.getString(listProfiles.getSelectedIndex()));
		} else if (aCmd == cmdExit) {
			destroyApp(false);
		}
		cachedCounter = INVALID_COUNTER;
	}

	// Protected methods -----------------------------------------------------

	/**
	 * Generates the current token. If the token can't be generated it returns
	 * an empty String.
	 * 
	 * @return current token or an empty String
	 */
	protected static String genToken(final long counter, final HMac hmac, final int digits) {
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

	/**
	 * Returns counter value for given time and timeStep.
	 * 
	 * @param timeInSec
	 * @param timeStep
	 * @return counter (HOTP)
	 */
	protected static long getCounter(final long timeInSec, final int timeStep) {
		return timeStep > 0 ? timeInSec / timeStep : INVALID_COUNTER;
	}

	// Private methods -------------------------------------------------------

	/**
	 * Returns HMac.
	 * 
	 * @return
	 */
	private synchronized HMac getHMac() {
		return hmac;
	}

	/**
	 * Sets HMac.
	 * 
	 * @param hmac
	 */
	private synchronized void setHMac(HMac hmac) {
		this.hmac = hmac;
	}

	/**
	 * Validates (and makes basic corrections in) the options form. It returns
	 * warning message(s) if the validation error occurs. An empty string is
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
		gauValidity.setMaxValue((keyLen > 0 && step > 1) ? step - 1 : INDEFINITE);

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

		int delta = 0;
		try {
			delta = Integer.parseInt(tfDelta.getString());
		} catch (NumberFormatException e) {
			tfDelta.setString(Integer.toString(DEFAULT_DELTA));
		}
		if (Math.abs(delta) > DAY_IN_SEC) {
			if (warnings.length() > 0)
				warnings.append("\n");
			warnings.append("Time correction is limited by one day (").append(DAY_IN_SEC).append(" sec).");
		}
		return warnings.toString();
	}

	/**
	 * Shows {@link Alert} warning screen with given message.
	 * 
	 * @param msg
	 * @param nextDisplayable
	 *            Next screen, which is displayed after warning confirmation by
	 *            a user.
	 */
	private void displayAlert(final String msg, Displayable nextDisplayable) {
		alertWarn.setString(msg);
		Display.getDisplay(this).setCurrent(alertWarn, nextDisplayable);
	}

	/**
	 * Adds new profile to {@link RecordStore} and returns ID of the new record.
	 * It returns -1 if adding fails.
	 * 
	 * @param configBytes
	 *            byte array profile representation
	 * @return new record ID or -1 (if adding fails)
	 */
	private int addProfileToRecordStore(final byte[] configBytes) {
		RecordStore tmpRS = null;
		try {
			tmpRS = RecordStore.openRecordStore(STORE_PROFILE_CONFIG, true);
			return tmpRS.addRecord(configBytes, 0, configBytes.length);
		} catch (Exception e) {
			debugErr("addProfile - " + e.getClass().getName() + " - " + e.getMessage());
		} finally {
			if (tmpRS != null) {
				try {
					tmpRS.closeRecordStore();
				} catch (RecordStoreException e) {
					debugErr("addProfile (close) - " + e.getClass().getName() + " - " + e.getMessage());
				}
			}
		}
		return -1;
	}

	/**
	 * Removes record with given ID from a {@link RecordStore} with given name.
	 * 
	 * @param storeName
	 * @param recordId
	 */
	private void removeRecordFromStore(final String storeName, final int recordId) {
		RecordStore tmpRS = null;
		if (DEBUG)
			debug("removeRecordFromStore - " + storeName + " - " + recordId);
		try {
			tmpRS = RecordStore.openRecordStore(storeName, false);
			tmpRS.deleteRecord(recordId);
		} catch (RecordStoreNotFoundException e) {
			if (DEBUG)
				debug("removeRecordFromStore - RecordStoreNotFoundException - " + storeName);
		} catch (Exception e) {
			debugErr("removeRecordFromStore - " + e.getClass().getName() + " - " + storeName + " - " + recordId + ": "
					+ e.getMessage());
		} finally {
			if (tmpRS != null) {
				try {
					tmpRS.closeRecordStore();
				} catch (RecordStoreException e) {
					debugErr("removeRecordFromStore (close) - " + e.getClass().getName() + " - " + storeName + " - "
							+ recordId + ": " + e.getMessage());
				}
			}
		}
	}

	/**
	 * Sets record with given ID and value to a {@link RecordStore} with given
	 * name.
	 * 
	 * @param storeName
	 * @param recordId
	 * @param value
	 * @return
	 */
	private boolean saveRecordToStore(final String storeName, final int recordId, final byte[] value) {
		RecordStore tmpRS = null;
		try {
			tmpRS = RecordStore.openRecordStore(storeName, true);
			tmpRS.setRecord(recordId, value, 0, value.length);
		} catch (Exception e) {
			debugErr("saveRecordToStore - " + e.getClass().getName() + " - " + storeName + " - " + recordId + ": "
					+ e.getMessage());
			return false;
		} finally {
			if (tmpRS != null) {
				try {
					tmpRS.closeRecordStore();
				} catch (RecordStoreException e) {
					debugErr("saveRecordToStore (close) - " + e.getClass().getName() + " - " + storeName + " - "
							+ recordId + ": " + e.getMessage());
				}
			}
		}
		return true;
	}

	/**
	 * Loads value of a record with given ID from a {@link RecordStore} with
	 * given name.
	 * 
	 * @param storeName
	 * @param recordId
	 * @return
	 */
	private byte[] loadRecordFromStore(final String storeName, final int recordId) {
		RecordStore tmpRS = null;
		byte[] value = EMPTY_BYTE_ARRAY;
		try {
			tmpRS = RecordStore.openRecordStore(storeName, false);
			value = tmpRS.getRecord(recordId);
		} catch (RecordStoreNotFoundException e) {
			if (DEBUG) {
				debug("loadRecordFromStore - RecordStoreNotFoundException - " + storeName);
			}
		} catch (Exception e) {
			debugErr("loadRecordFromStore - " + e.getClass().getName() + " - " + storeName + " - " + recordId + ": "
					+ e.getMessage());
		} finally {
			if (tmpRS != null) {
				try {
					tmpRS.closeRecordStore();
				} catch (RecordStoreException e) {
					debugErr("loadRecordFromStore (close) - " + e.getClass().getName() + " - " + storeName + " - "
							+ recordId + ": " + e.getMessage());
				}
			}
		}
		return value;
	}

	/**
	 * Removes profile with given index from GUI list and the
	 * {@link RecordStore}.
	 * 
	 * @param profileIdx
	 */
	private void removeProfile(final int profileIdx) {
		if (profileIdx >= listProfiles.size() || profileIdx < 0) {
			return;
		}
		listProfiles.delete(profileIdx);
		listProfiles.setSelectedIndex(profileIdx < listProfiles.size() ? profileIdx : profileIdx - 1, true);
		removeRecordFromStore(STORE_PROFILE_CONFIG, recordIds[profileIdx]);
		int[] newRecIds = new int[recordIds.length - 1];
		System.arraycopy(recordIds, 0, newRecIds, 0, profileIdx);
		System.arraycopy(recordIds, profileIdx + 1, newRecIds, profileIdx, newRecIds.length - profileIdx);
		recordIds = newRecIds;
	}

	/**
	 * Loads configuration of the selected profile.
	 */
	private void loadSelectedProfile() {
		final int profileIdx = listProfiles.getSelectedIndex();

		// load from profile
		debug("Loading profile config record.");
		final byte[] profileConfig = loadRecordFromStore(STORE_PROFILE_CONFIG, recordIds[profileIdx]);
		ByteArrayInputStream bais = new ByteArrayInputStream(profileConfig);
		DataInputStream dis = new DataInputStream(bais);
		String base32EncodedSecret = null;
		try {
			tfProfile.setString(dis.readUTF());
			byte[] key = new byte[dis.readByte()];
			dis.readFully(key);
			base32EncodedSecret = base32Encode(key);
			tfTimeStep.setString(String.valueOf(dis.readInt()));
			chgHmacAlgorithm.setSelectedIndex(dis.readInt(), true);
			tfDigits.setString(String.valueOf(dis.readByte()));
			tfDelta.setString(String.valueOf(dis.readInt()));
		} catch (Exception e) {
			e.printStackTrace();
			debugErr("loading profile configuration - " + e.getClass().getName() + " - " + e.getMessage());
		} finally {
			try {
				dis.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		tfSecret.setString(base32EncodedSecret);
		siProfile.setText(tfProfile.getString());
		siToken.setText("");
		int timeStep = -1;
		try {
			timeStep = Integer.parseInt(tfTimeStep.getString());
		} catch (NumberFormatException e) {
			debugErr(e.getMessage());
		}
		gauValidity.setMaxValue((base32EncodedSecret.length() > 0 && timeStep > 1) ? timeStep - 1 : INDEFINITE);
		if (base32EncodedSecret.length() == 0) {
			final Display display = Display.getDisplay(this);
			display.setCurrent(fOptions);
		} else {
			// use validation - to check loaded data
			commandAction(cmdOK, null);
		}
	}

	/**
	 * Loads list of profile names and IDs from the {@link RecordStore}.
	 */
	private void loadProfiles() {
		RecordStore tmpRS = null;
		recordIds = new int[0];
		try {
			tmpRS = RecordStore.openRecordStore(STORE_PROFILE_CONFIG, true);
			if (tmpRS.getNumRecords() == 0) {
				byte[] newRecord = DEFAULT_CONFIG_BYTES;

				// try to load old-style (1.3) configuration
				byte[] secret = loadRecordFromStore(STORE_KEY_OLD, 1);
				if (secret.length > 0) {
					debug("Loading old config.");

					final byte[] configBytes = loadRecordFromStore(STORE_CONFIG_OLD, 1);
					final ByteArrayInputStream bais = new ByteArrayInputStream(configBytes);
					final DataInputStream dis = new DataInputStream(bais);
					int ts = DEFAULT_TIMESTEP, idx = DEFAULT_HMAC_ALG_IDX, delta = DEFAULT_DELTA;
					int digits = DEFAULT_DIGITS;

					try {
						ts = dis.readInt();
						idx = dis.readInt();
						digits = dis.readByte();
						delta = dis.readInt();
					} catch (Exception e) {
						debugErr("loading old configuration - " + e.getClass().getName() + " - " + e.getMessage());
					} finally {
						try {
							dis.close();
						} catch (IOException e) {
							debugErr("loading old configuration (close) - " + e.getClass().getName() + " - "
									+ e.getMessage());
						}
					}
					newRecord = getProfileConfig(DEFAULT_PROFILE, secret, ts, idx, digits, delta);

					try {
						RecordStore.deleteRecordStore(STORE_KEY_OLD);
					} catch (RecordStoreException e) {
						//nothing to do here
					}
					try {
						RecordStore.deleteRecordStore(STORE_CONFIG_OLD);
					} catch (RecordStoreException e) {
						//nothing to do here
					}
				}

				debug("Adding new configuration record.");
				tmpRS.addRecord(newRecord, 0, newRecord.length);
			}
			//load profile record IDs
			recordIds = new int[tmpRS.getNumRecords()];
			RecordEnumeration recEnum = tmpRS.enumerateRecords(null, null, false);
			int i = 0;
			while (recEnum.hasNextElement()) {
				recordIds[i++] = recEnum.nextRecordId();
			}
			//sort record IDs
			for (i = 0; i < recordIds.length; i++) {
				for (int j = (recordIds.length - 1); j >= (i + 1); j--) {
					if (recordIds[j] < recordIds[j - 1]) {
						final int tmp = recordIds[j];
						recordIds[j] = recordIds[j - 1];
						recordIds[j - 1] = tmp;
					}
				}
			}
			// load profile names
			for (i = 0; i < recordIds.length; i++) {
				final int recordId = recordIds[i];
				debug("Parsing profile name for record " + recordId);
				final String profileName = parseProfileName(tmpRS.getRecord(recordId));
				debug("Parsed profile name: " + profileName);
				listProfiles.append(profileName, null);
			}
			if (listProfiles.getSelectedIndex() < 0)
				listProfiles.setSelectedIndex(0, true);
		} catch (Exception e) {
			debugErr("loadProfiles - " + e.getClass().getName() + " - " + e.getMessage());
		} finally {
			if (tmpRS != null) {
				try {
					tmpRS.closeRecordStore();
				} catch (RecordStoreException e) {
					debug("loadProfiles (close) - " + e.getClass().getName() + " - " + e.getMessage());
				}
			}
		}
	}

	/**
	 * Returns profile name from given profile record value.
	 * 
	 * @param profileBytes
	 * @return profile name
	 */
	private String parseProfileName(byte[] profileBytes) {
		final ByteArrayInputStream bais = new ByteArrayInputStream(profileBytes);
		final DataInputStream dis = new DataInputStream(bais);
		try {
			return dis.readUTF();
		} catch (IOException e) {
			debugErr(e.getMessage());
		} finally {
			try {
				dis.close();
			} catch (IOException e) {
				debugErr(e.getMessage());
			}
		}
		return DEFAULT_PROFILE;
	}

	/**
	 * Saves profile to a record store.
	 */
	private void save() {
		final int profileIdx = listProfiles.getSelectedIndex();
		final int recordId = recordIds[profileIdx];

		//store configuration of current profile
		final byte[] configBytes = getProfileConfig(tfProfile.getString(), base32Decode(tfSecret.getString()),
				Integer.parseInt(tfTimeStep.getString()), chgHmacAlgorithm.getSelectedIndex(),
				Integer.parseInt(tfDigits.getString()), Integer.parseInt(tfDelta.getString()));
		saveRecordToStore(STORE_PROFILE_CONFIG, recordId, configBytes);

		// update also profile name
		listProfiles.set(profileIdx, tfProfile.getString(), null);
	}

	/**
	 * Creates profile record from provided values.
	 * 
	 * @param profileName
	 * @param key
	 * @param timeStep
	 * @param hmacIdx
	 * @param digits
	 * @param delta
	 * @return
	 */
	private static byte[] getProfileConfig(String profileName, byte[] key, int timeStep, int hmacIdx, int digits,
			int delta) {
		if (key == null)
			key = EMPTY_BYTE_ARRAY;
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		final DataOutputStream dos = new DataOutputStream(baos);
		try {
			dos.writeUTF(profileName);
			dos.writeByte(key.length);
			dos.write(key);
			dos.writeInt(timeStep);
			dos.writeInt(hmacIdx);
			dos.writeByte(digits);
			dos.writeInt(delta);
		} catch (IOException e) {
			debugErr("Creating configuration failed - " + e.getMessage());
		} finally {
			try {
				dos.close();
			} catch (IOException e) {
				debugErr("Creating configuration failed (close)- " + e.getMessage());
			}
		}
		return baos.toByteArray();
	}

	/**
	 * Debug function
	 * 
	 * @param aWhat
	 */
	private static void debug(final String aWhat) {
		if (DEBUG) {
			System.out.println(">>>DEBUG " + aWhat);
		}
	}

	/**
	 * Debug function for errors
	 * 
	 * @param aWhat
	 */
	private static void debugErr(final String aWhat) {
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
	 * Encodes byte array to Base32 String. Returns not-null String.
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

			// Is the current digit going to span a byte boundary?
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

	/**
	 * Generates a new random secret key.
	 * 
	 * @return secret key suitable for selected HMac Algorithm
	 */
	private byte[] generateNewKey() {
		byte[] result = new byte[HMAC_BYTE_COUNT[chgHmacAlgorithm.getSelectedIndex()]];
		for (int i = 0, len = result.length; i < len;)
			for (int rnd = rand.nextInt(), n = Math.min(len - i, 4); n-- > 0; rnd >>= 8)
				result[i++] = (byte) rnd;
		return result;
	}

	/**
	 * Returns lenght of Base32 encoded string for the given count of bytes.
	 * 
	 * @param byteCount
	 * @return
	 */
	private static int getBase32Len(int byteCount) {
		return byteCount / 5 * 8 + BASE32_LEN[byteCount % 5];
	}

	/**
	 * Zero-left-padding for integer values. If a length of given integer
	 * converted to string is smaller than len, then zeroes are filled on the
	 * left side so the resulting string has lenght=len.
	 * 
	 * @param value
	 * @param len
	 * @return
	 */
	private static String zeroLeftPad(int value, int len) {
		final String strValue = String.valueOf(value);
		if (strValue.length() >= len)
			return strValue;
		final StringBuffer sb = new StringBuffer(len);
		for (int i = strValue.length(); i < len; i++) {
			sb.append("0");
		}
		return sb.append(strValue).toString();
	}

	// Embedded classes ------------------------------------------------------

	/**
	 * Task for refreshing the token.
	 */
	private class RefreshTokenTask extends TimerTask {

		public final void run() {
			int timeStep = -1;
			try {
				timeStep = Integer.parseInt(tfTimeStep.getString());
			} catch (NumberFormatException e) {
				debugErr(e.getMessage());
			}

			int remainSec = -1;
			if (timeStep > 0) {
				int delta = DEFAULT_DELTA;
				try {
					delta = Integer.parseInt(tfDelta.getString());
				} catch (NumberFormatException e) {
					debugErr(e.getMessage());
				}
				final long currentTimeSec = System.currentTimeMillis() / 1000L + delta;
				final long newCounter = getCounter(currentTimeSec, timeStep);
				if (cachedCounter != newCounter) {
					int digits = -1;
					try {
						digits = Integer.parseInt(tfDigits.getString());
					} catch (NumberFormatException e) {
						debugErr(e.getMessage());
					}
					siToken.setText(genToken(newCounter, getHMac(), digits));
					cachedCounter = newCounter;
				}
				if (timeStep == 1 || "".equals(siToken.getText())) {
					remainSec = IDLE;
				} else {
					remainSec = (int) (timeStep - 1 - currentTimeSec % timeStep);
				}
			} else {
				remainSec = 0;
				siToken.setText("");
				cachedCounter = INVALID_COUNTER;
			}
			// set values (and repaint) only if needed
			if (gauValidity.getValue() != remainSec) {
				gauValidity.setValue(remainSec);
			}
		}
	}
}
