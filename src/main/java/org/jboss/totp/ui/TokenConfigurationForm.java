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

import java.util.Random;

import javax.microedition.lcdui.Choice;
import javax.microedition.lcdui.ChoiceGroup;
import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.TextField;

import org.jboss.totp.Base32;
import org.jboss.totp.Context;
import org.jboss.totp.HMACAlgorithm;
import org.jboss.totp.Token;

/**
 * @author Josef Cacek
 * @author Lukas Krejci
 */
public class TokenConfigurationForm extends AbstractForm {

    private static final int[] HMAC_BYTE_COUNT = { 160 / 8, 256 / 8, 512 / 8 };

    private final TextField txtName = new TextField("Name", null, 255, TextField.ANY);
    private final TextField txtSecretBase32 = new TextField("Key (Base32)", null, 255, TextField.ANY);
    private final TextField txtTimeStep = new TextField("Time Step (sec)", "30", 3, TextField.NUMERIC);
    private final TextField txtPassCodeLength = new TextField("Number of Digits", "6", 1, TextField.NUMERIC);
    private final TextField txtTimeDelta = new TextField("Time Correction (sec)", "0", 3, TextField.NUMERIC);
    private final ChoiceGroup chgHmacAlgorithm = new ChoiceGroup("HMAC algorithm", Choice.EXCLUSIVE);

    private static String getFormTitle(Token token) {
        String name = token == null ? "New Token" : token.getName();
        return name + " Configuration";
    }

    public TokenConfigurationForm() {
        super("");

        append(txtName);
        append(txtSecretBase32);
        append(txtTimeStep);
        append(txtPassCodeLength);
        append(txtTimeDelta);
        append(chgHmacAlgorithm);

        chgHmacAlgorithm.append("SHA1", null);
        chgHmacAlgorithm.append("SHA256", null);
        chgHmacAlgorithm.append("SHA512", null);

        addCommand(new Command("Generate Key", Command.SCREEN, 1));
        addCommand(new Command("Save", Command.OK, 1));
        addCommand(new Command("Cancel", Command.CANCEL, 1));
    }

    protected void handleScreen(Command c) {
        byte[] newKey = generateNewKey();
        txtSecretBase32.setString(Base32.encode(newKey));
    }

    protected void handleOk(Command c) {
        int idx = getContext().getActiveTokenIndex();
        if (idx < 0) {
            //new token
            getContext().getTokens().addElement(getTokenFromInput());
        } else {
            //updating existing token
            getContext().getTokens().setElementAt(getTokenFromInput(), idx);
        }
        getContext().switchTo(Context.MAIN_FORM);
    }

    protected void handleCancel(Command c) {
        getContext().switchTo(Context.MAIN_FORM);
    }

    public void refresh() {
        Token token = null;

        int idx = getContext().getActiveTokenIndex();
        if (idx >= 0) {
            token = (Token) getContext().getTokens().elementAt(idx);
        }

        setTitle(getFormTitle(token));

        if (token == null) {
            txtName.setString("");
            txtSecretBase32.setString("");
            txtTimeStep.setString("30");
            txtPassCodeLength.setString("6");
            txtTimeDelta.setString("0");
            chgHmacAlgorithm.setSelectedIndex(0, true);
        } else {
            txtName.setString(token.getName());
            txtSecretBase32.setString(token.getKey());
            txtTimeStep.setString(Integer.toString(token.getTimeStep()));
            txtTimeDelta.setString(Integer.toString(token.getTimeDelta()));
            switch(token.getHmacAlgorithm()) {
            case HMACAlgorithm.SHA_1:
                chgHmacAlgorithm.setSelectedIndex(0, true);
                break;
            case HMACAlgorithm.SHA_256:
                chgHmacAlgorithm.setSelectedIndex(0, true);
                break;
            case HMACAlgorithm.SHA_512:
                chgHmacAlgorithm.setSelectedIndex(0, true);
                break;
            default:
                chgHmacAlgorithm.setSelectedIndex(0, true);
            }
        }
    }

    private Token getTokenFromInput() {
        String name = txtName.getString();
        String key = txtSecretBase32.getString();
        //TODO validation
        int timeStep = Integer.parseInt(txtTimeStep.getString());
        int timeDelta = Integer.parseInt(txtTimeDelta.getString());
        byte passCodeLength = Byte.parseByte(txtPassCodeLength.getString());
        byte hmacAlgorithm = HMACAlgorithm.SHA_1;
        switch (chgHmacAlgorithm.getSelectedIndex()) {
        case 0:
            hmacAlgorithm = HMACAlgorithm.SHA_1;
            break;
        case 1:
            hmacAlgorithm = HMACAlgorithm.SHA_256;
            break;
        case 2:
            hmacAlgorithm = HMACAlgorithm.SHA_512;
            break;
        }

        return new Token(name, hmacAlgorithm, timeStep, key, passCodeLength, timeDelta);
    }

    private byte[] generateNewKey() {
        byte[] result = new byte[HMAC_BYTE_COUNT[chgHmacAlgorithm.getSelectedIndex()]];
        for (int i = 0, len = result.length; i < len;)
            for (int rnd = new Random().nextInt(), n = Math.min(len - i, 4); n-- > 0; rnd >>= 8)
                result[i++] = (byte) rnd;
        return result;
    }

}
