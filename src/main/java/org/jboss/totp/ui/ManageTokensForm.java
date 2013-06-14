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

import javax.microedition.lcdui.Alert;
import javax.microedition.lcdui.AlertType;
import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Displayable;
import javax.microedition.lcdui.List;

import org.jboss.totp.Context;
import org.jboss.totp.Token;

/**
 * @author Josef Cacek
 * @author Lukas Krejci
 */
public class ManageTokensForm extends List implements Refreshable, CommandListener {

    private Context context;

    private Alert alertDelete = new Alert("Delete", "Are sure to delete the token?", null, AlertType.CONFIRMATION);

    public ManageTokensForm() {
        super("Manage Tokens", List.IMPLICIT);
        addCommand(new Command("Edit", Command.SCREEN, 1));
        addCommand(new Command("Delete", Command.SCREEN, 2));
        addCommand(new Command("Back", Command.BACK, 3));
        setCommandListener(this);

        alertDelete.addCommand(new Command("Yes", Command.OK, 1));
        alertDelete.addCommand(new Command("No", Command.CANCEL, 1));
    }

    public void commandAction(Command c, Displayable d) {
        switch(c.getCommandType()) {
        case Command.BACK:
            handleBack(c);
            break;
        case Command.SCREEN:
            handleScreen(c);
            break;
        }
    }

    public void init(Context context) {
        this.context = context;
    }

    protected Context getContext() {
        return context;
    }

    protected void handleBack(Command c) {
        getContext().switchTo(Context.MAIN_FORM);
    }

    protected void handleScreen(Command c) {
        final int idx = getSelectedIndex();

        switch(c.getPriority()) {
        case 1: //edit
            getContext().setActiveTokenIndex(idx);
            getContext().switchTo(Context.TOKEN_CONFIGURATION_FORM);
            break;
        case 2: //delete
            alertDelete.setCommandListener(new CommandListener() {
                public void commandAction(Command c, Displayable d) {
                    switch(c.getCommandType()) {
                    case Command.OK:
                        getContext().getTokens().removeElementAt(idx);
                    }
                    getContext().switchTo(Context.MANAGE_TOKENS_FORM);
                }
            });
            getContext().displayAlert(alertDelete);
            break;
        }
    }

    public void refresh() {
        Enumeration en = getContext().getTokens().elements();

        deleteAll();

        while(en.hasMoreElements()) {
            Token token = (Token) en.nextElement();

            append(token.getName(), null);
        }
    }
}
