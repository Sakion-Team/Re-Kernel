package nep.timeline.freezer.core.utils;

public class StringUtils {
    public static String getSubString(String text, String left, String right) {
        String result;
        int zLen;
        if (left == null || left.isEmpty()) {
            zLen = 0;
        } else {
            zLen = text.indexOf(left);
            if (zLen > -1)
                zLen += left.length();
            else
                zLen = 0;
        }
        int yLen = text.indexOf(right, zLen);
        if (yLen < 0 || right.isEmpty())
            yLen = text.length();
        result = text.substring(zLen, yLen);
        return result;
    }

    public static int StringToInteger(String str) {
        String data = str.trim();
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < data.length(); i++) {
            char c = data.charAt(i);
            if (Character.isDigit(c))
                result.append(c);
        }

        try {
            return Integer.parseInt(result.toString());
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }
}
