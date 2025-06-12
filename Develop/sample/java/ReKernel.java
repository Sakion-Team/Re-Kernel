public class ReKernel {
    private static boolean isRunning = false;
    private static final int NETLINK_UNIT_DEFAULT = 22;
    private static final int NETLINK_UNIT_MAX = 26;
    private static final Handler rekernel = new Handler(new HandlerThread("ReKernel").getLooper());
    private static final ExecutorService executorService = Executors.newSingleThreadExecutor();

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

    public static void start() {
        if (isRunning)
            return;

        executorService.execute(() -> {
            try {
                int netlinkUnit;
                int configNetlinkUnit = Settings.netlinkUnit;
                if (configNetlinkUnit >= NETLINK_UNIT_DEFAULT && configNetlinkUnit <= NETLINK_UNIT_MAX) {
                    netlinkUnit = configNetlinkUnit;
                } else {
                    File dir = new File("/proc/rekernel");
                    if (dir.exists()) {
                        File[] files = dir.listFiles();
                        if (files == null) {
                            // 找不到ReKernel单元
                            return;
                        }
                        File unitFile = files[0];
                        netlinkUnit = StringToInteger(unitFile.getName());
                    } else netlinkUnit = NETLINK_UNIT_DEFAULT;
                }

                try (NetlinkClient netlinkClient = new NetlinkClient(netlinkUnit)) {
                    if (!netlinkClient.getMDescriptor().valid()) {
                        // 连接失败
                        return;
                    }

                    netlinkClient.bind((SocketAddress) new NetlinkSocketAddress(100).toInstance());

                    isRunning = true;

                    // 连接成功

                    while (true) {
                        try {
                            ByteBuffer byteBuffer = netlinkClient.recvMessage();
                            String data = new String(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit(), StandardCharsets.UTF_8);
                            if (!data.isEmpty()) {
                                Map<String, String> params = parseParams(data.substring(data.indexOf("type"), data.lastIndexOf(";")));
                                rekernel.post(() -> {
                                    String type = params.get("type");
                                    if (type.equals("Binder")) {
                                        String bindertype = params.get("bindertype");
                                        int oneway = StringToInteger(params.get("oneway"));
                                        int fromPid = StringToInteger(params.get("from_pid"));
                                        int fromUid = StringToInteger(params.get("from"));
                                        int targetPid = StringToInteger(params.get("target_pid"));
                                        int targetUid = StringToInteger(params.get("target"));
                                        int rpcName = params.get("rpc_name");
                                        int code = StringToInteger(params.get("code"));
                                        // 你的代码
                                    } else if (type.equals("Signal")) {
                                        int targetPid = StringToInteger(params.get("dst_pid"));
                                        int targetUid = StringToInteger(params.get("dst"));
                                        int killerPid = StringToInteger(params.get("killer_pid"));
                                        int killerUid = StringToInteger(params.get("killer"));
                                        int signal = StringToInteger(params.get("signal"));
                                        // 你的代码
                                    } else if (type.equals("Network")) {
                                        int targetUid = StringToInteger(params.get("target"));
                                        String proto = params.get("proto");
                                        // 你的代码
                                    }
                                });
                            }
                        } catch (ErrnoException | InterruptedIOException | NumberFormatException ignored) {

                        } catch (Exception e) {
                            // 出现异常
                        }
                    }
                }
            } catch (ErrnoException | IOException e) {
                // 无法连接至ReKernel服务器
            } catch (Throwable ignored) {

            }
        });
    }
}
