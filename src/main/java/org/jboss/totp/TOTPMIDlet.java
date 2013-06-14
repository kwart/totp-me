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
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Timer;
import java.util.TimerTask;

import javax.microedition.lcdui.Display;
import javax.microedition.midlet.MIDlet;
import javax.microedition.midlet.MIDletStateChangeException;
import javax.microedition.rms.RecordStore;
import javax.microedition.rms.RecordStoreException;
import javax.microedition.rms.RecordStoreNotFoundException;

import org.jboss.totp.ui.MainForm;
import org.jboss.totp.ui.ManageTokensForm;
import org.jboss.totp.ui.TokenConfigurationForm;

/**
 * @author Josef Cacek
 * @author Lukas Krejci
 */
public class TOTPMIDlet extends MIDlet {

    private static final boolean DEBUG = true;
    private static final String STORE_CONFIG = "config";

    private Context context;
    private final Timer timer = new Timer();
    private final RefreshTokenTask refreshTokenTask = new RefreshTokenTask();

    /**
     * Task for refreshing the token.
     */
    private class RefreshTokenTask extends TimerTask {
        public final void run() {
            if (context.getCurrentForm() == Context.MAIN_FORM) {
                context.switchTo(Context.MAIN_FORM);
            }
        }
    }

    protected void startApp() throws MIDletStateChangeException {
        try {
            context = new Context(this, new MainForm(), new TokenConfigurationForm(), new ManageTokensForm());

            loadTokens();

            final Display display = Display.getDisplay(this);

            if (context.getTokens().isEmpty()) {
                context.switchTo(Context.TOKEN_CONFIGURATION_FORM);
            } else {
                context.switchTo(Context.MAIN_FORM);
            }

            timer.schedule(refreshTokenTask, 0L, 1000L);
        } catch (Exception e) {
            debugErr("TOTPMIDlet.startApp() - " + e.getMessage());
            error(e);
        }
    }

    protected void pauseApp() {
    }

    protected void destroyApp(boolean unconditional) throws MIDletStateChangeException {
        try {
            saveTokens();
        } catch (Exception e) {
            debugErr("Saving config in destroyApp failed: " + e.getMessage());
            error(e);
        }
        refreshTokenTask.cancel();
        timer.cancel();
        notifyDestroyed();
    }

    private void loadTokens() throws RecordStoreException {
        RecordStore tmpRS = null;

        try {
            tmpRS = RecordStore.openRecordStore(STORE_CONFIG, false);
            if (tmpRS == null) {
                return;
            }

            for(int i = 0; i < tmpRS.getNumRecords(); ++i) {
                byte[] bytes = tmpRS.getRecord(i + 1);

                ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
                DataInputStream dis = new DataInputStream(bais);

                context.getTokens().addElement(Token.readFrom(dis));

                dis.close();
            }
        } catch (RecordStoreNotFoundException e) {
            debugErr(e.getMessage());
        } catch (Exception e) {
            error(e);
            if (tmpRS != null) {
                tmpRS.closeRecordStore();
                tmpRS = null;
                RecordStore.deleteRecordStore(STORE_CONFIG);
            }
        } finally {
            if (tmpRS != null) {
                tmpRS.closeRecordStore();
            }
        }

    }

    private void saveTokens() throws RecordStoreException, IOException {
        RecordStore tmpRS = null;

        try {
            tmpRS = RecordStore.openRecordStore(STORE_CONFIG, true);

            int min = Math.min(context.getTokens().size(), tmpRS.getNumRecords());
            int max = Math.max(context.getTokens().size(), tmpRS.getNumRecords());
            boolean newTokens = tmpRS.getNumRecords() == min;

            int i = 0;
            for(; i < min; ++i) {
                Token token = (Token) context.getTokens().elementAt(i);
                byte[] bytes = token.serialize();

                tmpRS.setRecord(i + 1, bytes, 0, bytes.length);
            }

            if (newTokens) {
                for(; i < max; ++i) {
                    Token token = (Token) context.getTokens().elementAt(i);
                    byte[] bytes = token.serialize();

                    tmpRS.addRecord(bytes, 0, bytes.length);
                }
            } else {
                for(; i < max; ++i) {
                    tmpRS.deleteRecord(tmpRS.getNumRecords());
                }
            }
        } finally {
            if (tmpRS != null) {
                tmpRS.closeRecordStore();
            }
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
}
