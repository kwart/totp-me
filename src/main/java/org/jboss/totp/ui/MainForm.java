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

package org.jboss.totp.ui;

import java.util.Enumeration;

import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.Gauge;
import javax.microedition.lcdui.StringItem;

import org.jboss.totp.Context;
import org.jboss.totp.Token;

/**
 * @author Josef Cacek
 * @author Lukas Krejci
 */
public class MainForm extends AbstractForm {

    private int nofViewedTokens;

    public MainForm() {
        super("TOTP ME ${project.version}");
        addCommand(new Command("Exit", Command.EXIT, 1));
        addCommand(new Command("Add Token", Command.SCREEN, 1));
        addCommand(new Command("Manage Tokens", Command.SCREEN, 2));
    }

    protected void handleExit(Command c) {
        getContext().destroyApp();
    }

    protected void handleScreen(Command c) {
        getContext().setActiveTokenIndex(-1);
        switch(c.getPriority()) {
        case 1:
            getContext().switchTo(Context.TOKEN_CONFIGURATION_FORM);
            break;
        case 2:
            getContext().switchTo(Context.MANAGE_TOKENS_FORM);
            break;
        }
    }

    public void refresh() {
        int currentToken = 0;
        Enumeration en = getContext().getTokens().elements();

        while(en.hasMoreElements() && currentToken < nofViewedTokens) {
            Token token = (Token) en.nextElement();

            StringItem string = (StringItem) get(currentToken * 2);
            Gauge validity = (Gauge) get(currentToken * 2 + 1);

            String label = string.getLabel();
            String text = string.getText();
            int val = validity.getValue();

            if (!token.getName().equals(label)) {
                string.setLabel(token.getName());
            }

            if (!token.getCurrentPassCode().equals(text)) {
                string.setText(token.getCurrentPassCode());
            }

            if (val != token.getRemainingValidTime()) {
                validity.setValue(token.getRemainingValidTime());
            }

            ++currentToken;
        }

        while(en.hasMoreElements()) {
            Token token = (Token) en.nextElement();

            StringItem string = new StringItem(token.getName(), token.getCurrentPassCode());
            Gauge validity = new Gauge(null, false, token.getTimeStep() - 1, token.getTimeStep());

            append(string);
            append(validity);

            ++currentToken;
        }

        while(nofViewedTokens > currentToken) {
            --nofViewedTokens;
            delete(nofViewedTokens * 2 + 1);
            delete(nofViewedTokens * 2);
        }

        nofViewedTokens = currentToken;
    }

    private static void debug(String message) {
        System.err.println(message);
    }
}
