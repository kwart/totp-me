package cz.cacek.test;

import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Display;
import javax.microedition.lcdui.Displayable;
import javax.microedition.lcdui.Form;
import javax.microedition.lcdui.TextField;
import javax.microedition.midlet.MIDlet;
import javax.microedition.rms.RecordStore;
import javax.microedition.rms.RecordStoreException;
import javax.microedition.rms.RecordStoreNotFoundException;

public class TestMIDlet extends MIDlet implements CommandListener {

    private static final boolean DEBUG = true;

    private static final String RS_NOTE = "note";
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

    private Command cmdExit = new Command("Exit", Command.EXIT, 1);
    private final TextField tfNote = new TextField("Note", null, 1024, TextField.ANY);
    // http://docs.oracle.com/javame/config/cldc/ref-impl/midp2.0/jsr118/javax/microedition/lcdui/TextField.htm getMaxSize

    private final Form fMain = new Form("Test");

    /**
     * Constructor - initializes GUI components.
     */
    public TestMIDlet() {
        fMain.append(tfNote);
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
            byte[] notebytes = loadRecordFromStore(RS_NOTE);
            tfNote.setString(new String(notebytes, "UTF-8"));
            Display.getDisplay(this).setCurrent(fMain);
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
        String txt = tfNote.getString();
        try {
            saveRecordToStore(RS_NOTE, txt == null ? EMPTY_BYTE_ARRAY : txt.getBytes("UTF-8"));
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
        debug("Command action: " + aCmd == null ? null : aCmd.getLabel());
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
    private boolean saveRecordToStore(final String storeName, final byte[] value) {
        RecordStore tmpRS = null;
        try {
            tmpRS = RecordStore.openRecordStore(storeName, true);
            if (tmpRS.getNumRecords() < 1) {
                tmpRS.addRecord(value, 0, value.length);
            } else {
                tmpRS.setRecord(1, value, 0, value.length);
            }
        } catch (Exception e) {
            debugErr("saveRecordToStore - " + e.getClass().getName() + " - " + storeName + ": " + e.getMessage());
            return false;
        } finally {
            if (tmpRS != null) {
                try {
                    tmpRS.closeRecordStore();
                } catch (RecordStoreException e) {
                    debugErr("saveRecordToStore (close) - " + e.getClass().getName() + " - " + storeName + ": "
                            + e.getMessage());
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
    private byte[] loadRecordFromStore(final String storeName) {
        RecordStore tmpRS = null;
        byte[] value = null;
        try {
            tmpRS = RecordStore.openRecordStore(storeName, false);
            if (tmpRS.getNumRecords() > 0) {
                value = tmpRS.getRecord(1);
            }
        } catch (RecordStoreNotFoundException e) {
            debug("loadRecordFromStore - RecordStoreNotFoundException - " + storeName);
        } catch (Exception e) {
            debugErr("loadRecordFromStore - " + e.getClass().getName() + " - " + storeName + ": " + e.getMessage());
        } finally {
            if (tmpRS != null) {
                try {
                    tmpRS.closeRecordStore();
                } catch (RecordStoreException e) {
                    debugErr("loadRecordFromStore (close) - " + e.getClass().getName() + " - " + storeName + " "
                            + e.getMessage());
                }
            }
        }
        return value == null ? EMPTY_BYTE_ARRAY : value;
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
