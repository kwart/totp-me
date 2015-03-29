/*
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
package jp.comutt.otp;

import java.util.Hashtable;

import jp.comutt.utils.StringUtils;
import jp.comutt.utils.URLDecoder;


/**
 * otpauth URI parser
 *
 * @author comutt
 *
 */
public class OtpauthUri {

    public static class InvalidUriException extends Exception {
        private static final long serialVersionUID = 1L;

        public InvalidUriException(String message) {
            super(message);
        }
    }

    public static class TokenType {
        private final int value;

        private TokenType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static final TokenType HOTP = new TokenType(1);
        public static final TokenType TOTP = new TokenType(2);
    }

    private static final String OTPAUTH_URI_PREFIX = "otpauth://";

    private TokenType type;
    private String issuer;
    private String label;
    private String secret;
    private String algorithm;
    private Integer digits;
    private Integer period;
    private Long counter;
    private String image;

    private int qmarkIndex;

    private OtpauthUri(String uri) throws InvalidUriException {
        if (uri == null) {
            throw new InvalidUriException("uri is null");
        }
        else if (uri.equals("")) {
            throw new InvalidUriException("uri is empty");
        }
        else if (!uri.startsWith(OTPAUTH_URI_PREFIX)) {
            throw new InvalidUriException("uri does not starts with otpauth://");
        }

        parseBeforeParameters(uri);
        parseParameters(uri);
    }

    private void parseBeforeParameters(String uri) throws InvalidUriException {
        int prefixLength = OTPAUTH_URI_PREFIX.length();
        int slashIndex = uri.indexOf('/', prefixLength);
        if (slashIndex == -1) {
            throw new InvalidUriException("uri does not have /");
        }

        String typeString = uri.substring(prefixLength, slashIndex);

        if (typeString.equals("totp")) {
            type = TokenType.TOTP;
        }
        else if (typeString.equals("hotp")) {
            type = TokenType.HOTP;
        }
        else {
            throw new InvalidUriException("unknown otp type: type=" + typeString);
        }

        qmarkIndex = uri.indexOf('?', slashIndex);
        if (qmarkIndex == -1) {
            throw new InvalidUriException("uri does not have parameters");
        }

        String decodedPath = URLDecoder.decode(uri.substring(slashIndex + 1, qmarkIndex));
        int colonIndex = decodedPath.indexOf(':');

        if (colonIndex >= 0) {
            issuer = decodedPath.substring(0, colonIndex);
        }

        label = colonIndex >= 0 ? decodedPath.substring(colonIndex + 1) : decodedPath;
    }

    private void parseParameters(String uri) throws InvalidUriException {
        String paramString = uri.substring(qmarkIndex + 1);
        if (paramString.equals("")) {
            throw new InvalidUriException("uri have empty parameter");
        }

        Hashtable paramMap = new Hashtable();

        String[] paramPairs = StringUtils.split(paramString, '&');
        for (int i = 0; i < paramPairs.length; i++) {
            String pair = paramPairs[i];
            int equalIndex = pair.indexOf("=");

            String key = URLDecoder.decode(pair.substring(0, equalIndex));
            String value = URLDecoder.decode(pair.substring(equalIndex + 1));
            paramMap.put(key, value);
        }

        if (paramMap.containsKey("secret")) {
            secret = (String) paramMap.get("secret");
        }
        else {
            throw new InvalidUriException("uri does not have secret");
        }

        if (paramMap.containsKey("issuer")) {
            issuer = (String) paramMap.get("issuer");
        }

        if (paramMap.containsKey("algorithm")) {
            algorithm = (String) paramMap.get("algorithm");
        }

        if (paramMap.containsKey("digits")) {
            try {
                digits = new Integer(Integer.parseInt((String) paramMap.get("digits")));
            }
            catch (NumberFormatException e) {
                throw new InvalidUriException("uri has invalid digits: digits=" + paramMap.get("digits"));
            }
        }

        if (paramMap.containsKey("period")) {
            try {
                period = new Integer(Integer.parseInt((String) paramMap.get("period")));
            }
            catch (NumberFormatException e) {
                throw new InvalidUriException("uri has invalid period: period=" + paramMap.get("period"));
            }
        }

        if (paramMap.containsKey("image")) {
            image = (String) paramMap.get("image");
        }

        if (type == TokenType.HOTP) {
            if (paramMap.containsKey("counter")) {
                try {
                    counter = new Long(Long.parseLong((String) paramMap.get("counter")));
                }
                catch (NumberFormatException e) {
                    throw new InvalidUriException("uri has invalid counter: counter=" + paramMap.get("counter"));
                }
            }
        }
    }

    public static OtpauthUri parse(String uri) throws InvalidUriException {
        return new OtpauthUri(uri);
    }

    public TokenType getType() {
        return type;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getLabel() {
        return label;
    }

    public String getSecret() {
        return secret;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public Integer getDigits() {
        return digits;
    }

    public Integer getPeriod() {
        return period;
    }

    public Long getCounter() {
        return counter;
    }

    public String getImage() {
        return image;
    }

}
