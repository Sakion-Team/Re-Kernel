package org.sakion.rekernel;

import static org.sakion.rekernel.GenericUtils.DEFAULT_RECV_BUFSIZE;
import static org.sakion.rekernel.GenericUtils.GENL_HDRLEN;
import static org.sakion.rekernel.GenericUtils.GENL_VERSION;
import static org.sakion.rekernel.GenericUtils.NETLINK_ADD_MEMBERSHIP;
import static org.sakion.rekernel.GenericUtils.NETLINK_GENERIC;
import static org.sakion.rekernel.GenericUtils.NLA_HDRLEN;
import static org.sakion.rekernel.GenericUtils.NLMSG_HDRLEN;
import static org.sakion.rekernel.GenericUtils.NLM_F_REQUEST;
import static org.sakion.rekernel.GenericUtils.REKERNEL_A_UID;
import static org.sakion.rekernel.GenericUtils.REKERNEL_C_ADD_MONITOR_NET;
import static org.sakion.rekernel.GenericUtils.REKERNEL_C_DEL_MONITOR_NET;
import static org.sakion.rekernel.GenericUtils.SOCKET_RECV_BUFSIZE;
import static org.sakion.rekernel.GenericUtils.SOL_NETLINK;
import static org.sakion.rekernel.GenericUtils.extractEvent;
import static org.sakion.rekernel.GenericUtils.familyId;
import static org.sakion.rekernel.GenericUtils.mcastGroupId;
import static org.sakion.rekernel.GenericUtils.resolveFamily;

import android.os.Handler;
import android.os.HandlerThread;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import org.lsposed.hiddenapibypass.HiddenApiBypass;

import java.io.File;
import java.io.FileDescriptor;
import java.io.InterruptedIOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ReKernel {
    private ReKernel() {}

    private static volatile FileDescriptor fileDescriptor = null;
    private static volatile Callback cacheCallback = null;

    // --- Legacy ---
    private static boolean legacy = false;
    private static boolean defaultUnit = false;
    private static final int NETLINK_UNIT_DEFAULT = 22;
    private static final int NETLINK_UNIT_MAX = 26;
    private static final int USER_PORT = 100;          // legacy raw-netlink dest port (kernel USER_PORT)
    private static final int LEGACY_MSG_TYPE = 0x11;   // legacy raw-netlink nlmsg type
    // --------------

    public static boolean isRunning() {
        return fileDescriptor != null && fileDescriptor.valid();
    }

    public static boolean isLegacy() {
        return legacy;
    }

    public static boolean isDefaultUnit() {
        return defaultUnit;
    }

    private static final ExecutorService executorService = Executors.newSingleThreadExecutor();
    private static final HandlerThread THREAD = create();

    private static HandlerThread create() {
        HandlerThread t = new HandlerThread("Re-Kernel");
        t.start();
        return t;
    }

    private static final Handler HANDLER = new Handler(THREAD.getLooper());

    private static boolean sendCommand(byte cmd, boolean hasUid, int uid) {
        if (!isRunning() || familyId < 0)
            return false;

        try {
            int total = NLMSG_HDRLEN + GENL_HDRLEN + (hasUid ? (NLA_HDRLEN + 4) : 0);

            ByteBuffer byteBuffer = NetlinkUtils.nlBuf(total);
            NetlinkUtils.putNlMsgHdr(byteBuffer, total, familyId, NLM_F_REQUEST, 1, 0);
            NetlinkUtils.putGenlHdr(byteBuffer, cmd, GENL_VERSION);
            if (hasUid)
                NetlinkUtils.putAttrU32(byteBuffer, REKERNEL_A_UID, uid);

            try {
                Os.write(fileDescriptor, byteBuffer.array(), 0, total);
                return true;
            } catch (ErrnoException _) {
            }
        } catch (Throwable _) {
        }

        return false;
    }

    private static boolean monitorNet(int uid, boolean add) {
        if (!isRunning() || defaultUnit)
            return false;

        try {
            int total = NLMSG_HDRLEN + 8;
            ByteBuffer byteBuffer = NetlinkUtils.nlBuf(total);
            NetlinkUtils.putNlMsgHdr(byteBuffer, total, LEGACY_MSG_TYPE, NLM_F_REQUEST, 1, USER_PORT);
            byteBuffer.putInt(add ? 2 : 3); // raw legacy cmd type (MONITOR_NET=2, DEL_MONITOR_NET=3)
            byteBuffer.putInt(uid);

            try {
                Os.write(fileDescriptor, byteBuffer.array(), 0, total);
                return true;
            } catch (ErrnoException _) {
            }
        } catch (Throwable _) {
        }

        return false;
    }

    public static boolean addMonitorNet(int uid) {
        if (!isRunning())
            return false;

        if (legacy)
            return monitorNet(uid, true);

        return sendCommand(REKERNEL_C_ADD_MONITOR_NET, true, uid);
    }

    public static boolean delMonitorNet(int uid) {
        if (!isRunning())
            return false;

        if (legacy)
            return monitorNet(uid, false);

        return sendCommand(REKERNEL_C_DEL_MONITOR_NET, true, uid);
    }

    private static int startLegacy(Callback callback, boolean searchNetlinkUnit, int chooseNetlinkUnit) {
        try {
            int netlinkUnit;
            if (chooseNetlinkUnit >= NETLINK_UNIT_DEFAULT && chooseNetlinkUnit <= NETLINK_UNIT_MAX && !searchNetlinkUnit) {
                netlinkUnit = chooseNetlinkUnit;
            } else if (searchNetlinkUnit) {
                File dir = new File("/proc/rekernel");
                if (dir.exists()) {
                    File[] files = dir.listFiles();
                    if (files == null)
                        return -1;
                    File unitFile = files[0];
                    netlinkUnit = GenericUtils.StringToInteger(unitFile.getName());
                } else {
                    defaultUnit = true;
                    netlinkUnit = NETLINK_UNIT_DEFAULT;
                }
            } else {
                defaultUnit = true;
                netlinkUnit = NETLINK_UNIT_DEFAULT;
            }

            FileDescriptor descriptor = Os.socket(OsConstants.AF_NETLINK, OsConstants.SOCK_DGRAM, netlinkUnit);

            Os.setsockoptInt(descriptor, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, SOCKET_RECV_BUFSIZE);

            if (!descriptor.valid()) {
                GenericUtils.closeAndSignalBlockedThreads(fileDescriptor);
                return -1;
            }

            Os.bind(descriptor, (SocketAddress) HiddenApiBypass.newInstance(Class.forName("android.system.NetlinkSocketAddress"), 100, 0));

            fileDescriptor = descriptor;

            cacheCallback = callback;

            executorService.execute(() -> {
                if (!defaultUnit) {
                    try {
                        byte[] message = "#proc_remove\u0000".getBytes(StandardCharsets.UTF_8);
                        int total = NLMSG_HDRLEN + message.length;
                        ByteBuffer byteBuffer = NetlinkUtils.nlBuf(total);
                        NetlinkUtils.putNlMsgHdr(byteBuffer, total, LEGACY_MSG_TYPE, NLM_F_REQUEST, 1, USER_PORT);
                        byteBuffer.put(message);

                        try {
                            Os.write(descriptor, byteBuffer.array(), 0, total);
                        } catch (ErrnoException _) {
                        }
                    } catch (Throwable throwable) {
                        callback.exception(new IllegalStateException("FAILED_TO_SEND_MESSAGE_TO_RE_KERNEL_SERVER"));
                    }

                    try {
                        int total = NLMSG_HDRLEN + 4;
                        ByteBuffer byteBuffer = NetlinkUtils.nlBuf(total);
                        NetlinkUtils.putNlMsgHdr(byteBuffer, total, LEGACY_MSG_TYPE, NLM_F_REQUEST, 1, USER_PORT);
                        byteBuffer.putInt(1); // REMOVE_PROC CMD

                        try {
                            Os.write(descriptor, byteBuffer.array(), 0, total);
                        } catch (ErrnoException _) {
                        }
                    } catch (Throwable throwable) {
                        callback.exception(new IllegalStateException("FAILED_TO_SEND_MESSAGE_TO_RE_KERNEL_SERVER"));
                    }
                }

                while (true) {
                    try {
                        ByteBuffer byteBuffer = ByteBuffer.allocate(DEFAULT_RECV_BUFSIZE);
                        int length = Os.read(descriptor, byteBuffer);
                        byteBuffer.position(0);
                        byteBuffer.limit(length);
                        byteBuffer.order(ByteOrder.nativeOrder());
                        String data = new String(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit(), StandardCharsets.UTF_8);
                        if (!data.isEmpty())
                            HANDLER.post(() -> resolver(data, callback));
                    } catch (ErrnoException | StringIndexOutOfBoundsException |
                             InterruptedIOException | NumberFormatException ignored) {
                    } catch (Exception e) {
                        callback.exception(e);
                    }
                }
            });

            return defaultUnit ? -1 : netlinkUnit;
        } catch (Throwable ignored) {

        }

        return -1;
    }

    private static void resolver(String data, Callback callback) {
        int indexOf = data.indexOf("type");
        int lastIndexOf = data.lastIndexOf(";");
        if (indexOf < 0 || lastIndexOf < 0 || indexOf > lastIndexOf)
            return;

        String message = data.substring(indexOf, lastIndexOf);
        Map<String, String> params = new HashMap<>();
        for (String keyValue : message.split(",")) {
            String[] split = keyValue.split("=");
            if (split.length == 2)
                params.put(split[0].trim(), split[1].trim());
        }

        switch (params.get("type")) {
            case "Binder" -> {
                int binderType = switch (params.get("bindertype")) {
                    case "transaction" -> Callback.BINDER_TRANSACTION;
                    case "reply" -> Callback.BINDER_REPLY;
                    case "free_buffer_full" -> Callback.BINDER_FREE_BUFFER_FULL;
                    case null, default -> {
                        callback.exception(new IllegalStateException("Unknown binder type: " + params.get("bindertype")));
                        yield Callback.BINDER_UNKNOWN;
                    }
                };
                boolean oneway = GenericUtils.StringToInteger(params.get("oneway")) == 1;
                int fromPid = GenericUtils.StringToInteger(params.get("from_pid"));
                int fromUid = GenericUtils.StringToInteger(params.get("from"));
                int targetPid = GenericUtils.StringToInteger(params.get("target_pid"));
                int targetUid = GenericUtils.StringToInteger(params.get("target"));
                String rpcName = params.get("rpc_name");
                int code = GenericUtils.StringToInteger(params.get("code"));
                callback.binder(binderType, oneway, fromUid, fromPid, targetUid, targetPid, rpcName, code);
            }
            case "Signal" -> {
                int targetPid = GenericUtils.StringToInteger(params.get("dst_pid"));
                int targetUid = GenericUtils.StringToInteger(params.get("dst"));
                int killerPid = GenericUtils.StringToInteger(params.get("killer_pid"));
                int killerUid = GenericUtils.StringToInteger(params.get("killer"));
                int signal = GenericUtils.StringToInteger(params.get("signal"));
                callback.signal(signal, killerUid, killerPid, targetUid, targetPid);
            }
            case "Network" -> {
                int targetUid = GenericUtils.StringToInteger(params.get("target"));
                int proto = switch (params.get("proto")) {
                    case "ipv4" -> Callback.PROTO_IPV4;
                    case "ipv6" -> Callback.PROTO_IPV6;
                    case null, default -> {
                        callback.exception(new IllegalStateException("Unknown proto: " + params.get("proto")));
                        yield Callback.PROTO_UNKNOWN;
                    }
                };
                int dataLen = params.containsKey("data_len") ? GenericUtils.StringToInteger(params.get("data_len")) : Callback.DATA_LEN_UNKNOWN;
                callback.network(proto, targetUid, dataLen);
            }
            case null, default -> callback.exception(new IllegalStateException("Unknown type: " + params.get("type")));
        }
    }

    public static int registerListener(Callback callback, boolean searchNetlinkUnit, int chooseNetlinkUnit) {
        if (isRunning() || callback == null)
            return -1;

        try {
            FileDescriptor descriptor = Os.socket(OsConstants.AF_NETLINK, OsConstants.SOCK_DGRAM, NETLINK_GENERIC);

            Os.setsockoptInt(descriptor, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, SOCKET_RECV_BUFSIZE);

            if (!descriptor.valid()) {
                GenericUtils.closeAndSignalBlockedThreads(fileDescriptor);
                return -1;
            }

            Os.bind(descriptor, (SocketAddress) HiddenApiBypass.newInstance(Class.forName("android.system.NetlinkSocketAddress"), 0, 0));

            if (!resolveFamily(descriptor)) {
                GenericUtils.closeAndSignalBlockedThreads(fileDescriptor);
                // 解析Family失败 可能正在使用旧版模块
                legacy = true;
                return startLegacy(callback, searchNetlinkUnit, chooseNetlinkUnit);
            }

            if (mcastGroupId > 0)
                Os.setsockoptInt(descriptor, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, mcastGroupId);

            fileDescriptor = descriptor;

            cacheCallback = callback;

            executorService.execute(() -> {
                while (true) {
                    try {
                        ByteBuffer byteBuffer = ByteBuffer.allocate(DEFAULT_RECV_BUFSIZE);
                        int length = Os.read(descriptor, byteBuffer);
                        byteBuffer.order(ByteOrder.nativeOrder());
                        String data = extractEvent(byteBuffer, length);
                        if (data != null && !data.isEmpty())
                            HANDLER.post(() -> resolver(data, callback));
                    } catch (ErrnoException | StringIndexOutOfBoundsException |
                             InterruptedIOException | NumberFormatException ignored) {
                    } catch (Exception e) {
                        callback.exception(e);
                    }
                }
            });
            return 0;
        } catch (Throwable ignored) {

        }

        return -1;
    }

    public static void unregisterListener() {
        try {
            executorService.shutdownNow();
            GenericUtils.closeAndSignalBlockedThreads(fileDescriptor);
            cacheCallback.disconnected();
            cacheCallback = null;
        } catch (Throwable ignored) {
        }
    }

    public interface Callback {
        /** binderType: unknown */
        int BINDER_UNKNOWN          = -1;
        /** binderType: a binder transaction call */
        int BINDER_TRANSACTION      = 0;
        /** binderType: a binder transaction reply */
        int BINDER_REPLY            = 1;
        /** binderType: free-buffer exhaustion burst */
        int BINDER_FREE_BUFFER_FULL = 2;

        /** proto: IPv4 */
        int PROTO_IPV4 = 4;
        /** proto: IPv6 */
        int PROTO_IPV6 = 6;
        /** proto: unknown */
        int PROTO_UNKNOWN = -1;

        /** data length: unknown */
        int DATA_LEN_UNKNOWN = -1;

        /**
         * Called only when the NetLink connection drops unexpectedly
         * (receive error while still running). Not invoked on a clean
         * {@link ReKernel#unregisterListener()}.
         */
        void disconnected();

        /**
         * Called only when the reception error while running
         */
        void exception(Exception exception);

        /**
         * @param type {@link #BINDER_TRANSACTION}, {@link #BINDER_REPLY},
         *                   or {@link #BINDER_FREE_BUFFER_FULL}
         */
        void binder(int type, boolean oneway, int fromUid, int fromPid, int targetUid, int targetPid, String rpcName, int code);

        /**
         * @param signal   signal number sent
         * @param killerUid   uid of the process sending the signal
         * @param killerPid pid of the process sending the signal
         * @param targetUid      uid of the target process
         * @param targetPid   pid of the target process
         */
        void signal(int signal, int killerUid, int killerPid, int targetUid, int targetPid);

        /**
         * @param proto   {@link #PROTO_IPV4} or {@link #PROTO_IPV6}
         * @param targetUid  uid being monitored
         * @param dataLen length of the observed payload
         */
        void network(int proto, int targetUid, int dataLen);
    }
}
