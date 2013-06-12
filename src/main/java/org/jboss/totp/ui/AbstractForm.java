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

import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Displayable;
import javax.microedition.lcdui.Form;

import org.jboss.totp.Context;

/**
 * @author Josef Cacek
 * @author Lukas Krejci
 */
public abstract class AbstractForm extends Form implements CommandListener, Refreshable {

    private Context context;

    protected AbstractForm(String title) {
        super(title);
        this.setCommandListener(this);
    }

    public void init(Context ctx) {
        this.context = ctx;
    }

    public final void commandAction(Command c, Displayable d) {
        switch(c.getCommandType()) {
        case Command.BACK:
            handleBack(c);
            break;
        case Command.CANCEL:
            handleCancel(c);
            break;
        case Command.EXIT:
            handleExit(c);
            break;
        case Command.HELP:
            handleHelp(c);
            break;
        case Command.ITEM:
            handleItem(c);
            break;
        case Command.OK:
            handleOk(c);
            break;
        case Command.SCREEN:
            handleScreen(c);
            break;
        case Command.STOP:
            handleStop(c);
            break;
        }
    }

    protected Context getContext() {
        return context;
    }

    protected void handleBack(Command c) {

    }

    protected void handleCancel(Command c) {

    }

    protected void handleExit(Command c) {

    }

    protected void handleHelp(Command c) {

    }

    protected void handleItem(Command c) {

    }

    protected void handleOk(Command c) {

    }

    protected void handleScreen(Command c) {

    }

    protected void handleStop(Command c) {

    }
}
