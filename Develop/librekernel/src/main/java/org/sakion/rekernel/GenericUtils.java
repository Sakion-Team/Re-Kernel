package org.sakion.rekernel;

import android.system.ErrnoException;
import android.system.Os;

import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

class GenericUtils {
    private GenericUtils() {}

    static final int SOCKET_RECV_BUFSIZE = 64 * 1024;
    static final int DEFAULT_RECV_BUFSIZE = 8 * 1024;

    static final int NETLINK_GENERIC = 16;
    static final int SOL_NETLINK = 270;
    static final int NETLINK_ADD_MEMBERSHIP = 1;
    static final int GENL_ID_CTRL = 16;       // == NLMSG_MIN_TYPE, the "nlctrl" family
    static final int NLMSG_MIN_TYPE = 0x10;
    static final short NLM_F_REQUEST = 0x01;

    // Structural constants live in Netlink (the Android-free wire layer);
    // re-exported here so existing `import static ...GenericUtils.*` keep working.
    static final int NLMSG_HDRLEN = NetlinkUtils.NLMSG_HDRLEN;  // struct nlmsghdr
    static final int GENL_HDRLEN = NetlinkUtils.GENL_HDRLEN;    // struct genlmsghdr
    static final int NLA_HDRLEN = NetlinkUtils.NLA_HDRLEN;      // struct nlattr

    static final byte CTRL_CMD_GETFAMILY = 3;
    static final short CTRL_ATTR_FAMILY_ID = 1;
    static final short CTRL_ATTR_FAMILY_NAME = 2;
    static final short CTRL_ATTR_MCAST_GROUPS = 7;
    static final short CTRL_ATTR_MCAST_GRP_NAME = 1;
    static final short CTRL_ATTR_MCAST_GRP_ID = 2;

    static final String GENL_FAMILY_NAME = "rekernel";
    static final String GENL_MCGRP_NAME = "events";
    static final byte GENL_VERSION = 1;
    static final byte REKERNEL_C_EVENT = 1;             // kernel -> user
    static final byte REKERNEL_C_ADD_MONITOR_NET = 2;       // user -> kernel: add uid
    static final byte REKERNEL_C_DEL_MONITOR_NET = 3;   // user -> kernel: remove uid
    static final byte REKERNEL_C_KILL_NET = 4;          // user -> kernel: kill a pid's TCP/UDP sockets
    static final byte REKERNEL_C_GET_VERSION = 5;       // user -> kernel: query version (kernel replies unicast REKERNEL_A_MSG)
    static final short REKERNEL_A_MSG = 1;
    static final short REKERNEL_A_UID = 2;
    static final short REKERNEL_A_PID = 3;

    static volatile int familyId = -1;       // genl family id ("rekernel")
    static volatile int mcastGroupId = -1;    // genl multicast group id ("events")

    static void closeAndSignalBlockedThreads(FileDescriptor fd) throws IOException {
        if (fd == null) {
            return;
        }
        try {
            Os.close(fd);
        } catch (ErrnoException errnoException) {
            IOException exception = new IOException(errnoException.getMessage());
            exception.initCause(errnoException);
            throw exception;
        }
    }

    static boolean resolveFamily(FileDescriptor descriptor) {
        try {
            byte[] name = (GENL_FAMILY_NAME + "\u0000").getBytes(StandardCharsets.UTF_8);
            int total = NLMSG_HDRLEN + GENL_HDRLEN + NetlinkUtils.align4(NLA_HDRLEN + name.length);

            ByteBuffer byteBuffer = NetlinkUtils.nlBuf(total);
            NetlinkUtils.putNlMsgHdr(byteBuffer, total, GENL_ID_CTRL, NLM_F_REQUEST, 1, 0);
            NetlinkUtils.putGenlHdr(byteBuffer, CTRL_CMD_GETFAMILY, 1);
            NetlinkUtils.putAttrBytes(byteBuffer, CTRL_ATTR_FAMILY_NAME, name);

            Os.write(descriptor, byteBuffer.array(), 0, total);

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

    static boolean parseFamilyReply(ByteBuffer byteBuffer, int length) {
        if (length < NLMSG_HDRLEN + GENL_HDRLEN)
            return false;

        int nlmsgLen = byteBuffer.getInt(0);
        short nlmsgType = byteBuffer.getShort(4);
        if (nlmsgType != GENL_ID_CTRL)
            return false;

        int end = Math.min(nlmsgLen, length);
        int fId = -1;
        int grpId = -1;

        NetlinkUtils.AttrCursor attr = new NetlinkUtils.AttrCursor(byteBuffer, NLMSG_HDRLEN + GENL_HDRLEN, end);
        while (attr.next()) {
            if (attr.type == CTRL_ATTR_FAMILY_ID && attr.dataLen >= 2)
                fId = byteBuffer.getShort(attr.dataPos) & 0xFFFF;
            else if (attr.type == CTRL_ATTR_MCAST_GROUPS)
                grpId = parseMcastGroups(byteBuffer, attr.dataPos, attr.dataPos + attr.dataLen);
        }

        if (fId < 0)
            return false;

        familyId = fId;
        mcastGroupId = grpId;
        return true;
    }

    static int parseMcastGroups(ByteBuffer byteBuffer, int start, int end) {
        // Outer attrs are index-keyed group entries (type ignored); each nests name/id attrs.
        NetlinkUtils.AttrCursor group = new NetlinkUtils.AttrCursor(byteBuffer, start, end);
        while (group.next()) {
            String name = null;
            int id = -1;

            NetlinkUtils.AttrCursor attr = new NetlinkUtils.AttrCursor(
                    byteBuffer, group.dataPos, Math.min(group.dataPos + group.dataLen, end));
            while (attr.next()) {
                if (attr.type == CTRL_ATTR_MCAST_GRP_NAME)
                    name = NetlinkUtils.readString(byteBuffer, attr.dataPos, attr.dataLen);
                else if (attr.type == CTRL_ATTR_MCAST_GRP_ID && attr.dataLen >= 4)
                    id = byteBuffer.getInt(attr.dataPos);
            }

            if (GENL_MCGRP_NAME.equals(name))
                return id;
        }
        return -1;
    }

    static String extractEvent(ByteBuffer byteBuffer, int length) {
        return extractMsg(byteBuffer, length, REKERNEL_C_EVENT);
    }

    static String extractVersion(ByteBuffer byteBuffer, int length) {
        return extractMsg(byteBuffer, length, REKERNEL_C_GET_VERSION);
    }

    /** Read the REKERNEL_A_MSG string out of a genl message whose cmd matches {@code expectedCmd}. */
    private static String extractMsg(ByteBuffer byteBuffer, int length, int expectedCmd) {
        if (length < NLMSG_HDRLEN + GENL_HDRLEN)
            return null;

        int nlmsgLen = byteBuffer.getInt(0);
        short nlmsgType = byteBuffer.getShort(4);
        if (nlmsgType < NLMSG_MIN_TYPE)     // NLMSG_ERROR / NLMSG_DONE / control
            return null;

        int genlCmd = byteBuffer.get(NLMSG_HDRLEN) & 0xFF;
        if (genlCmd != expectedCmd)
            return null;

        NetlinkUtils.AttrCursor attr = new NetlinkUtils.AttrCursor(
                byteBuffer, NLMSG_HDRLEN + GENL_HDRLEN, Math.min(nlmsgLen, length));
        while (attr.next()) {
            if (attr.type == REKERNEL_A_MSG)
                return NetlinkUtils.readString(byteBuffer, attr.dataPos, attr.dataLen);
        }
        return null;
    }

    static int StringToInteger(String str) {
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
