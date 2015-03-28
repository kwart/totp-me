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

/**
 * String utils class
 *
 * @author comutt
 *
 */
public class StringUtils {

    /**
     * Split string with separator into an array
     *
     * This code came from
     * https://processing.org/discourse/alpha/board_Tools_action_display_num_1071761651.html
     *
     * @param s
     *          Target string
     * @param separator
     *          Split separator
     * @return
     *          An array of splitted string
     */
    public static String[] split(String s, char separator) {
        int cnt = 0, index;
        String parsed[], tmp;

        // Strip trailing separators...
        while (s.endsWith(String.valueOf(separator)))
            s = s.substring(0, s.length() - 1);

        // Find number of words in string
        for (int i = 0; i < s.length(); i++)
            if (s.charAt(i) == separator)
                cnt++;
        parsed = new String[cnt + 1];

        tmp = s;
        for (int i = 0; i < cnt + 1; i++) {
            index = tmp.indexOf(separator);
            if (index != -1) {
                parsed[i] = tmp.substring(0, index);
                tmp = tmp.substring(index + 1);
            } else
                parsed[i] = tmp;
        }

        return parsed;
    }

}
