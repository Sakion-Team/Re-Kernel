public class GenericReKernel {
    private static FileDescriptor fileDescriptor = null;

    /* resolved at runtime from the kernel via CTRL_CMD_GETFAMILY */
    private static volatile int familyId = -1;       // genl family id ("rekernel")
    private static volatile int mcastGroupId = -1;    // genl multicast group id ("events")

    private static final int SOCKET_RECV_BUFSIZE = 64 * 1024;
    private static final int DEFAULT_RECV_BUFSIZE = 8 * 1024;

    /* netlink / generic-netlink constants not exposed by OsConstants */
    private static final int NETLINK_GENERIC = 16;
    private static final int SOL_NETLINK = 270;
    private static final int NETLINK_ADD_MEMBERSHIP = 1;
    private static final int GENL_ID_CTRL = 16;       // == NLMSG_MIN_TYPE, the "nlctrl" family
    private static final int NLMSG_MIN_TYPE = 0x10;
    private static final short NLM_F_REQUEST = 0x01;

    /* header lengths (bytes) */
    private static final int NLMSG_HDRLEN = 16;       // struct nlmsghdr
    private static final int GENL_HDRLEN = 4;         // struct genlmsghdr
    private static final int NLA_HDRLEN = 4;          // struct nlattr
    private static final int NLA_TYPE_MASK = 0x3FFF;  // strip NLA_F_NESTED / NLA_F_NET_BYTEORDER

    /* generic-netlink control commands / attributes */
    private static final byte CTRL_CMD_GETFAMILY = 3;
    private static final short CTRL_ATTR_FAMILY_ID = 1;
    private static final short CTRL_ATTR_FAMILY_NAME = 2;
    private static final short CTRL_ATTR_MCAST_GROUPS = 7;
    private static final short CTRL_ATTR_MCAST_GRP_NAME = 1;
    private static final short CTRL_ATTR_MCAST_GRP_ID = 2;

    /* Re:Kernel genl protocol -- must match rekernel.h */
    private static final String GENL_FAMILY_NAME = "rekernel";
    private static final String GENL_MCGRP_NAME = "events";
    private static final byte GENL_VERSION = 1;
    private static final byte REKERNEL_C_EVENT = 1;             // kernel -> user
    private static final byte REKERNEL_C_MONITOR_NET = 2;       // user -> kernel: add uid
    private static final byte REKERNEL_C_DEL_MONITOR_NET = 3;   // user -> kernel: remove uid
    private static final short REKERNEL_A_MSG = 1;
    private static final short REKERNEL_A_UID = 2;

    private static final Handler rekernel = new Handler(new HandlerThread("Re-Kernel").getLooper());
    private static final ExecutorService executorService = Executors.newSingleThreadExecutor();

    private static int align4(int n) {
        return (n + 3) & ~3;
    }

    public static boolean isRunning() {
        return fileDescriptor != null && fileDescriptor.valid();
    }

    /*
     * Build and send a generic-netlink command to the kernel.
     * REKERNEL_C_MONITOR_NET / REKERNEL_C_DEL_MONITOR_NET carry a REKERNEL_A_UID attribute.
     */
    private static boolean sendCommand(byte cmd, boolean hasUid, int uid) {
        if (!isRunning() || familyId < 0)
            return false;

        try {
            int payloadLen = GENL_HDRLEN + (hasUid ? (NLA_HDRLEN + 4) : 0);
            int total = NLMSG_HDRLEN + payloadLen;

            byte[] bytes = new byte[total];
            ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
            byteBuffer.order(ByteOrder.nativeOrder());

            // struct nlmsghdr
            byteBuffer.putInt(total);
            byteBuffer.putShort((short) familyId);
            byteBuffer.putShort(NLM_F_REQUEST);
            byteBuffer.putInt(1);   // seq
            byteBuffer.putInt(0);   // pid (0 -> kernel assigns)

            // struct genlmsghdr
            byteBuffer.put(cmd);
            byteBuffer.put(GENL_VERSION);
            byteBuffer.putShort((short) 0);

            // optional REKERNEL_A_UID attribute (NLA_U32)
            if (hasUid) {
                byteBuffer.putShort((short) (NLA_HDRLEN + 4)); // nla_len = 8
                byteBuffer.putShort(REKERNEL_A_UID);
                byteBuffer.putInt(uid);
            }

            try {
                Os.write(fileDescriptor, bytes, 0, bytes.length);
                return true;
            } catch (ErrnoException _) {
            }
        } catch (Throwable _) {
        }

        return false;
    }

    public static boolean monitorNet(int uid) {
        return sendCommand(REKERNEL_C_MONITOR_NET, true, uid);
    }

    public static boolean delMonitorNet(int uid) {
        return sendCommand(REKERNEL_C_DEL_MONITOR_NET, true, uid);
    }

    private static boolean resolveFamily(FileDescriptor descriptor) {
        try {
            byte[] name = (GENL_FAMILY_NAME + "\u0000").getBytes(StandardCharsets.UTF_8);
            int attrLen = NLA_HDRLEN + name.length;             // nla_len (unpadded)
            int total = NLMSG_HDRLEN + GENL_HDRLEN + align4(attrLen);

            byte[] bytes = new byte[total];
            ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
            byteBuffer.order(ByteOrder.nativeOrder());

            // struct nlmsghdr
            byteBuffer.putInt(total);
            byteBuffer.putShort((short) GENL_ID_CTRL);
            byteBuffer.putShort(NLM_F_REQUEST);
            byteBuffer.putInt(1);   // seq
            byteBuffer.putInt(0);   // pid

            // struct genlmsghdr
            byteBuffer.put(CTRL_CMD_GETFAMILY);
            byteBuffer.put((byte) 1);   // controller version
            byteBuffer.putShort((short) 0);

            // CTRL_ATTR_FAMILY_NAME
            byteBuffer.putShort((short) attrLen);
            byteBuffer.putShort(CTRL_ATTR_FAMILY_NAME);
            byteBuffer.put(name);
            // trailing alignment padding is already zero (fresh array)

            Os.write(descriptor, bytes, 0, bytes.length);

            ByteBuffer reply = ByteBuffer.allocate(DEFAULT_RECV_BUFSIZE);
            int length = Os.read(descriptor, reply);
            if (length <= 0)
                return false;
            reply.order(ByteOrder.nativeOrder());

            return parseFamilyReply(reply, length);
        } catch (Throwable _) {
            return false;
        }
    }

    private static boolean parseFamilyReply(ByteBuffer byteBuffer, int length) {
        if (length < NLMSG_HDRLEN + GENL_HDRLEN)
            return false;

        int nlmsgLen = byteBuffer.getInt(0);
        short nlmsgType = byteBuffer.getShort(4);
        if (nlmsgType != GENL_ID_CTRL)      // NLMSG_ERROR / unexpected
            return false;

        int end = Math.min(nlmsgLen, length);
        int pos = NLMSG_HDRLEN + GENL_HDRLEN;   // skip genlmsghdr

        int fId = -1;
        int grpId = -1;

        while (pos + NLA_HDRLEN <= end) {
            int nlaLen = byteBuffer.getShort(pos) & 0xFFFF;
            int nlaType = byteBuffer.getShort(pos + 2) & NLA_TYPE_MASK;
            if (nlaLen < NLA_HDRLEN)
                break;

            int dataPos = pos + NLA_HDRLEN;
            int dataLen = nlaLen - NLA_HDRLEN;

            if (nlaType == CTRL_ATTR_FAMILY_ID && dataLen >= 2) {
                fId = byteBuffer.getShort(dataPos) & 0xFFFF;
            } else if (nlaType == CTRL_ATTR_MCAST_GROUPS) {
                grpId = parseMcastGroups(byteBuffer, dataPos, dataPos + dataLen);
            }

            pos += align4(nlaLen);
        }

        if (fId < 0)
            return false;

        familyId = fId;
        mcastGroupId = grpId;
        return true;
    }

    /* CTRL_ATTR_MCAST_GROUPS is an array of nested groups, each with a NAME + ID. */
    private static int parseMcastGroups(ByteBuffer byteBuffer, int start, int end) {
        int pos = start;
        while (pos + NLA_HDRLEN <= end) {
            int outerLen = byteBuffer.getShort(pos) & 0xFFFF;   // one group entry (nested)
            if (outerLen < NLA_HDRLEN)
                break;

            int innerStart = pos + NLA_HDRLEN;
            int innerEnd = Math.min(pos + outerLen, end);

            String name = null;
            int id = -1;

            int ip = innerStart;
            while (ip + NLA_HDRLEN <= innerEnd) {
                int aLen = byteBuffer.getShort(ip) & 0xFFFF;
                int aType = byteBuffer.getShort(ip + 2) & NLA_TYPE_MASK;
                if (aLen < NLA_HDRLEN)
                    break;

                int aData = ip + NLA_HDRLEN;
                int aDataLen = aLen - NLA_HDRLEN;

                if (aType == CTRL_ATTR_MCAST_GRP_NAME) {
                    name = readString(byteBuffer, aData, aDataLen);
                } else if (aType == CTRL_ATTR_MCAST_GRP_ID && aDataLen >= 4) {
                    id = byteBuffer.getInt(aData);
                }

                ip += align4(aLen);
            }

            if (GENL_MCGRP_NAME.equals(name))
                return id;

            pos += align4(outerLen);
        }
        return -1;
    }

    /* Pull the REKERNEL_A_MSG string out of a REKERNEL_C_EVENT multicast message. */
    private static String extractEvent(ByteBuffer byteBuffer, int length) {
        if (length < NLMSG_HDRLEN + GENL_HDRLEN)
            return null;

        int nlmsgLen = byteBuffer.getInt(0);
        short nlmsgType = byteBuffer.getShort(4);
        if (nlmsgType < NLMSG_MIN_TYPE)     // NLMSG_ERROR / NLMSG_DONE / control
            return null;

        int genlCmd = byteBuffer.get(NLMSG_HDRLEN) & 0xFF;
        if (genlCmd != REKERNEL_C_EVENT)
            return null;

        int end = Math.min(nlmsgLen, length);
        int pos = NLMSG_HDRLEN + GENL_HDRLEN;

        while (pos + NLA_HDRLEN <= end) {
            int nlaLen = byteBuffer.getShort(pos) & 0xFFFF;
            int nlaType = byteBuffer.getShort(pos + 2) & NLA_TYPE_MASK;
            if (nlaLen < NLA_HDRLEN)
                break;

            int dataPos = pos + NLA_HDRLEN;
            int dataLen = nlaLen - NLA_HDRLEN;

            if (nlaType == REKERNEL_A_MSG)
                return readString(byteBuffer, dataPos, dataLen);

            pos += align4(nlaLen);
        }
        return null;
    }

    private static String readString(ByteBuffer byteBuffer, int dataPos, int dataLen) {
        int strLen = dataLen;
        while (strLen > 0 && byteBuffer.get(dataPos + strLen - 1) == 0)
            strLen--;   // trim trailing NUL terminator(s)
        byte[] out = new byte[strLen];
        for (int i = 0; i < strLen; i++)
            out[i] = byteBuffer.get(dataPos + i);
        return new String(out, StandardCharsets.UTF_8);
    }

    public static void start(ClassLoader classLoader) {
        if (isRunning() || Build.VERSION.SDK_INT < Build.VERSION_CODES.Q)
            return;

        executorService.execute(() -> {
            try {
                FileDescriptor descriptor = Os.socket(OsConstants.AF_NETLINK, OsConstants.SOCK_DGRAM, NETLINK_GENERIC);

                Class<?> libcore = CakeReflection.findClass("libcore.io.Libcore", classLoader);
                Object os = CakeReflection.getStaticObjectField(libcore, "os");
                CakeReflection.callMethod(os, "setsockoptInt", descriptor, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, SOCKET_RECV_BUFSIZE);

                if (!descriptor.valid()) {
                    CakeReflection.callStaticMethod(CakeReflection.findClass("libcore.io.IoUtils", classLoader), "closeQuietly", descriptor);
                    // 连接失败
                    return;
                }

                Os.bind(descriptor, (SocketAddress) CakeReflection.newInstance(CakeReflection.findClass("android.system.NetlinkSocketAddress", classLoader), 0, 0));

                if (!resolveFamily(descriptor)) {
                    CakeReflection.callStaticMethod(CakeReflection.findClass("libcore.io.IoUtils", classLoader), "closeQuietly", descriptor);
                    // 解析Family失败 可能正在使用旧版模块
                    LegacyReKernel.start(classLoader);
                    return;
                }

                if (mcastGroupId > 0)
                    CakeReflection.callMethod(os, "setsockoptInt", descriptor, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, mcastGroupId);

                fileDescriptor = descriptor;

                // 连接成功

                while (true) {
                    try {
                        ByteBuffer byteBuffer = ByteBuffer.allocate(DEFAULT_RECV_BUFSIZE);
                        int length = Os.read(descriptor, byteBuffer);
                        if (length == DEFAULT_RECV_BUFSIZE)
                            Log.w("maximum read");
                        byteBuffer.order(ByteOrder.nativeOrder());
                        String data = extractEvent(byteBuffer, length);
                        if (data != null && !data.isEmpty())
                            rekernel.post(() -> ReKernel.onEvent(data));
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
