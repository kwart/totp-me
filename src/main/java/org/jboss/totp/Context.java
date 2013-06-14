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

import java.util.Vector;

import javax.microedition.lcdui.Alert;
import javax.microedition.lcdui.Display;
import javax.microedition.lcdui.Displayable;
import javax.microedition.midlet.MIDletStateChangeException;

import org.jboss.totp.ui.MainForm;
import org.jboss.totp.ui.ManageTokensForm;
import org.jboss.totp.ui.Refreshable;
import org.jboss.totp.ui.TokenConfigurationForm;

/**
 * @author Josef Cacek
 * @author Lukas Krejci
 */
public class Context {
    private final Vector tokens = new Vector();
    private final TOTPMIDlet midlet;
    private final Display display;
    private final MainForm mainForm;
    private final TokenConfigurationForm tokenConfigurationForm;
    private final ManageTokensForm manageTokensForm;

    private int currentForm = -1;
    private boolean inAlert = false;
    private int activeTokenIndex = -1;

    public static final int MAIN_FORM = 0;
    public static final int TOKEN_CONFIGURATION_FORM = 1;
    public static final int MANAGE_TOKENS_FORM = 2;

    public Context(TOTPMIDlet midlet, MainForm mainForm, TokenConfigurationForm tokenConfigurationForm, ManageTokensForm manageTokensForm) {
        this.midlet = midlet;
        this.mainForm = mainForm;
        this.tokenConfigurationForm = tokenConfigurationForm;
        this.manageTokensForm = manageTokensForm;

        this.display = Display.getDisplay(midlet);

        mainForm.init(this);
        tokenConfigurationForm.init(this);
        manageTokensForm.init(this);
    }

    public Vector getTokens() {
        return tokens;
    }

    public void switchTo(int formId) {
        Displayable form = getFormObject(formId);

        if (form instanceof Refreshable) {
            ((Refreshable) form).refresh();
        }

        if (currentForm != formId || inAlert) {
            inAlert = false;
            currentForm = formId;
            display.setCurrent(form);
        }
    }

    public void displayAlert(Alert alert) {
        inAlert = true;
        display.setCurrent(alert);
    }

    public int getCurrentForm() {
        return currentForm;
    }

    private Displayable getFormObject(int formId) {
        switch(formId) {
        case MAIN_FORM:
            return mainForm;
        case TOKEN_CONFIGURATION_FORM:
            return tokenConfigurationForm;
        case MANAGE_TOKENS_FORM:
            return manageTokensForm;
        default:
            return null;
        }
    }

    public int getActiveTokenIndex() {
        return activeTokenIndex;
    }

    public void setActiveTokenIndex(int activeTokenIndex) {
        this.activeTokenIndex = activeTokenIndex;
    }

    public void destroyApp() {
        try {
            midlet.destroyApp(false);
        } catch (MIDletStateChangeException e) {
            e.printStackTrace();
        }
    }
}
