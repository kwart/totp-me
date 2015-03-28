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
package jp.comutt.utils;

import java.io.ByteArrayOutputStream;

/**
 * This code came from:
 * http://jcs.mobile-utopia.com/jcs/919_URLDecoder.java
 *
 * Turns Strings of x-www-form-urlEncoded format into regular text.
 *
 * @version 1.0, 4/3/1996
 * @author Elliotte Rusty Harold
 */
public class URLDecoder {

    private URLDecoder() {
    }

    /**
     * Translates String from x-www-form-urlEncoded format into text.
     *
     * @param s
     *            String to be translated
     * @return the translated String.
     */
    public static String decode(String s) {

        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());

        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);
            if (c == '+') {
                out.write(' ');
            } else if (c == '%') {
                int c1 = Character.digit(s.charAt(++i), 16);
                int c2 = Character.digit(s.charAt(++i), 16);
                out.write((char) (c1 * 16 + c2));
            } else {
                out.write(c);
            }
        }

        return out.toString();
    }

}
