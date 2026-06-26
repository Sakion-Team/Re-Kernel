public class ReKernel {
    private static FileDescriptor fileDescriptor = null;
    private static boolean defaultUnit = false;
    private static final int NETLINK_UNIT_DEFAULT = 22;
    private static final int NETLINK_UNIT_MAX = 26;
    private static final int SOCKET_RECV_BUFSIZE = 64 * 1024;
    private static final int DEFAULT_RECV_BUFSIZE = 8 * 1024;
    private static final Handler rekernel = new Handler(new HandlerThread("Re-Kernel").getLooper());
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

    public static boolean isRunning() {
        return fileDescriptor != null && fileDescriptor.valid();
    }

    public static boolean monitorNet(int uid) {
        if (!isRunning() || defaultUnit)
            return false;

        try {
            byte[] payload = new byte[8];
            ByteBuffer cmdBuf = ByteBuffer.wrap(payload);
            cmdBuf.order(ByteOrder.nativeOrder());
            cmdBuf.putInt(2);
            cmdBuf.putInt(uid);

            byte[] bytes = new byte[16 + payload.length];
            ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
            byteBuffer.order(ByteOrder.nativeOrder());

            byteBuffer.putInt(bytes.length);
            byteBuffer.putShort((short) 0x11);
            byteBuffer.putShort((short) 0x1);
            byteBuffer.putInt(1);
            byteBuffer.putInt(100);
            byteBuffer.put(payload);

            try {
                Os.write(fileDescriptor, bytes, 0, bytes.length);
                return true;
            } catch (ErrnoException _) {
            }
        } catch (Throwable _) {
        }

        return false;
    }

    public static void start(ClassLoader classLoader) {
        if (isRunning() || Build.VERSION.SDK_INT < Build.VERSION_CODES.Q)
            return;

        executorService.execute(() -> {
            try {
                int netlinkUnit;
                int configNetlinkUnit = Settings.netlinkUnit;
                if (configNetlinkUnit >= NETLINK_UNIT_DEFAULT && configNetlinkUnit <= NETLINK_UNIT_MAX && !Settings.searchNetlinkUnit) {
                    netlinkUnit = configNetlinkUnit;
                } else if (Settings.searchNetlinkUnit) {
                    File dir = new File("/proc/rekernel");
                    if (dir.exists()) {
                        File[] files = dir.listFiles();
                        if (files == null) {
                            // 找不到ReKernel单元
                            return;
                        }
                        File unitFile = files[0];
                        Settings.netlinkUnit = netlinkUnit = StringUtils.StringToInteger(unitFile.getName());
                        Settings.save();
                    } else {
                        defaultUnit = true;
                        netlinkUnit = NETLINK_UNIT_DEFAULT;
                    }
                } else {
                    defaultUnit = true;
                    netlinkUnit = NETLINK_UNIT_DEFAULT;
                }

                FileDescriptor descriptor = Os.socket(OsConstants.AF_NETLINK, OsConstants.SOCK_DGRAM, netlinkUnit);

                Class<?> libcore = CakeReflection.findClass("libcore.io.Libcore", classLoader);
                Object os = CakeReflection.getStaticObjectField(libcore, "os");
                CakeReflection.callMethod(os, "setsockoptInt", descriptor, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, SOCKET_RECV_BUFSIZE);

                if (!descriptor.valid()) {
                    CakeReflection.callStaticMethod(CakeReflection.findClass("libcore.io.IoUtils", classLoader), "closeQuietly", descriptor);
                    // 连接失败
                    return;
                }

                Os.bind(descriptor, (SocketAddress) CakeReflection.newInstance(CakeReflection.findClass("android.system.NetlinkSocketAddress", classLoader), 100, 0));

                fileDescriptor = descriptor;

                // 连接成功
                if (!defaultUnit) {
                    try {
                        byte[] message = "#proc_remove\u0000".getBytes(StandardCharsets.UTF_8);
                        byte[] bytes = new byte[16 + message.length];
                        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
                        byteBuffer.order(ByteOrder.nativeOrder());

                        byteBuffer.putInt(bytes.length);
                        byteBuffer.putShort((short) 0x11);
                        byteBuffer.putShort((short) 0x1);
                        byteBuffer.putInt(1);
                        byteBuffer.putInt(100);

                        byteBuffer.put(message);

                        try {
                            Os.write(descriptor, bytes, 0, bytes.length);
                        } catch (ErrnoException _) {
                        }
                    } catch (Throwable throwable) {
                        // 销毁/proc/rekernel目录失败
                    }

                    try {
                        byte[] payload = new byte[4];
                        ByteBuffer cmdBuf = ByteBuffer.wrap(payload);
                        cmdBuf.order(ByteOrder.nativeOrder());
                        cmdBuf.putInt(1);

                        byte[] bytes = new byte[16 + payload.length];
                        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
                        byteBuffer.order(ByteOrder.nativeOrder());

                        byteBuffer.putInt(bytes.length);
                        byteBuffer.putShort((short) 0x11);
                        byteBuffer.putShort((short) 0x1);
                        byteBuffer.putInt(1);
                        byteBuffer.putInt(100);
                        byteBuffer.put(payload);

                        try {
                            Os.write(descriptor, bytes, 0, bytes.length);
                        } catch (ErrnoException _) {
                        }
                    } catch (Throwable throwable) {
                        // 销毁/proc/rekernel目录失败
                    }
                }

                while (true) {
                    try {
                        ByteBuffer byteBuffer = ByteBuffer.allocate(DEFAULT_RECV_BUFSIZE);
                        int length = Os.read(descriptor, byteBuffer);
                        if (length == DEFAULT_RECV_BUFSIZE)
                            Log.w("maximum read");
                        byteBuffer.position(0);
                        byteBuffer.limit(length);
                        byteBuffer.order(ByteOrder.nativeOrder());
                        String data = new String(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit(), StandardCharsets.UTF_8);
                        if (!data.isEmpty()) {
                            Map<String, String> params = parseParams(data.substring(data.indexOf("type"), data.lastIndexOf(";")));
                            rekernel.post(() -> {
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
                                        int rpcName = params.get("rpc_name");
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
                            });
                        }
                    } catch (ErrnoException | StringIndexOutOfBoundsException | InterruptedIOException | NumberFormatException ignored) {

                    } catch (Exception e) {
                        // 出现异常
                    }
                }
            } catch (ErrnoException | IOException e) {
                // 无法连接至ReKernel服务器
            } catch (Throwable ignored) {

            }
        });
    }
}
