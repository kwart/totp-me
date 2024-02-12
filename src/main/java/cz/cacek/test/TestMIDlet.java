package cz.cacek.test;

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

public class TestMIDlet extends MIDlet implements CommandListener {

    private static final boolean DEBUG = false;

    private static final String RS_NOTE = "note";
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

    private Command cmdExit = new Command("Exit", Command.EXIT, 1);
    private final StringItem siNote = new StringItem("Note", null);
    // http://docs.oracle.com/javame/config/cldc/ref-impl/midp2.0/jsr118/javax/microedition/lcdui/TextField.htm getMaxSize

    private final Form fMain = new Form("Test");

    /**
     * Constructor - initializes GUI components.
     */
    public TestMIDlet() {

        // Main display
        fMain.append(siNote);
        fMain.addCommand(cmdExit);
        fMain.setCommandListener(this);
    }

    /**
     * Loads configuration and initializes token-refreshing timer.
     * 
     * @see javax.microedition.midlet.MIDlet#startApp()
     */
    public void startApp() {
        try {
            byte[] notebytes = loadRecordFromStore(RS_NOTE, 0);
            siNote.setText(new String(notebytes, "UTF-8"));
        } catch (Exception e) {
            debugErr("startApp() - " + e.getMessage());
            error(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
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
        String txt = siNote.getText();
        try {
            saveRecordToStore(RS_NOTE, 0, txt == null ? EMPTY_BYTE_ARRAY : txt.getBytes("UTF-8"));
        } catch (Exception e) {
            debugErr("destroyApp() - " + e.getMessage());
            error(e);
        }
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
            debug("Command action: " + aCmd.getLabel());
        }
        if (aCmd == cmdExit) {
            destroyApp(false);
        }
    }

    /**
     * Sets record with given ID and value to a {@link RecordStore} with given name.
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
                    debugErr("saveRecordToStore (close) - " + e.getClass().getName() + " - " + storeName + " - " + recordId
                            + ": " + e.getMessage());
                }
            }
        }
        return true;
    }

    /**
     * Loads value of a record with given ID from a {@link RecordStore} with given name.
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
                    debugErr("loadRecordFromStore (close) - " + e.getClass().getName() + " - " + storeName + " - " + recordId
                            + ": " + e.getMessage());
                }
            }
        }
        return value;
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

}
