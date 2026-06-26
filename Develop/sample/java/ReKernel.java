public class ReKernel {
    public static boolean isRunning() {
        return GenericReKernel.isRunning() || LegacyReKernel.isRunning();
    }

    public static boolean monitorNet(int uid) {
        if (GenericReKernel.isRunning())
            return GenericReKernel.monitorNet(uid);
        return LegacyReKernel.monitorNet(uid, true);
    }

    public static boolean delMonitorNet(int uid) {
        if (GenericReKernel.isRunning())
            return GenericReKernel.delMonitorNet(uid);
        return LegacyReKernel.monitorNet(uid, false);
    }

    public static void onEvent(String data) {
        int typeIdx = data.indexOf("type");
        int semiIdx = data.lastIndexOf(";");
        if (typeIdx < 0 || semiIdx < typeIdx)
            continue;
        Map<String, String> params = parseParams(data.substring(typeIdx, semiIdx));
        String type = params.get("type");
        if (type == null)
            return;

        switch (type) {
            case "Binder" -> {
                String bindertype = params.get("bindertype");
                int oneway = StringToInteger(params.get("oneway"));
                int fromPid = StringToInteger(params.get("from_pid"));
                int fromUid = StringToInteger(params.get("from"));
                int targetPid = StringToInteger(params.get("target_pid"));
                int targetUid = StringToInteger(params.get("target"));
                String rpcName = params.get("rpc_name");
                int code = StringToInteger(params.get("code"));
                // 你的代码
             }
             case "Signal" -> {
                 int targetPid = StringToInteger(params.get("dst_pid"));
                 int targetUid = StringToInteger(params.get("dst"));
                 int killerPid = StringToInteger(params.get("killer_pid"));
                 int killerUid = StringToInteger(params.get("killer"));
                 int signal = StringToInteger(params.get("signal"));
                 // 你的代码
             }
             case "Network" -> {
                 int targetUid = StringToInteger(params.get("target"));
                 String proto = params.get("proto");
                 // 你的代码
             }
         }
    }

    private static Map<String, String> parseParams(String message) {
        Map<String, String> map = new HashMap<>();
        for (String keyValue : message.split(",")) {
            String[] split = keyValue.split("=");
            if (split.length == 2)
                map.put(split[0].trim(), split[1].trim());
        }
        return map;
    }

    private static int StringToInteger(String str) {
        if (str == null || str.isEmpty())
            return -1;

        try {
            String data = str.trim();
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < data.length(); i++) {
                char c = data.charAt(i);
                if (Character.isDigit(c))
                    result.append(c);
            }

            return Integer.parseInt(result.toString());
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }
}
