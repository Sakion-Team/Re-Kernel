package org.sakion.rekernel;

import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;

import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public class GenericUtils {
    protected static final int SOCKET_RECV_BUFSIZE = 64 * 1024;
    protected static final int DEFAULT_RECV_BUFSIZE = 8 * 1024;

    protected static final int NETLINK_GENERIC = 16;
    protected static final int SOL_NETLINK = 270;
    protected static final int NETLINK_ADD_MEMBERSHIP = 1;
    protected static final int GENL_ID_CTRL = 16;       // == NLMSG_MIN_TYPE, the "nlctrl" family
    protected static final int NLMSG_MIN_TYPE = 0x10;
    protected static final short NLM_F_REQUEST = 0x01;

    protected static final int NLMSG_HDRLEN = 16;       // struct nlmsghdr
    protected static final int GENL_HDRLEN = 4;         // struct genlmsghdr
    protected static final int NLA_HDRLEN = 4;          // struct nlattr
    protected static final int NLA_TYPE_MASK = 0x3FFF;  // strip NLA_F_NESTED / NLA_F_NET_BYTEORDER

    protected static final byte CTRL_CMD_GETFAMILY = 3;
    protected static final short CTRL_ATTR_FAMILY_ID = 1;
    protected static final short CTRL_ATTR_FAMILY_NAME = 2;
    protected static final short CTRL_ATTR_MCAST_GROUPS = 7;
    protected static final short CTRL_ATTR_MCAST_GRP_NAME = 1;
    protected static final short CTRL_ATTR_MCAST_GRP_ID = 2;

    protected static final String GENL_FAMILY_NAME = "rekernel";
    protected static final String GENL_MCGRP_NAME = "events";
    protected static final byte GENL_VERSION = 1;
    protected static final byte REKERNEL_C_EVENT = 1;             // kernel -> user
    protected static final byte REKERNEL_C_ADD_MONITOR_NET = 2;       // user -> kernel: add uid
    protected static final byte REKERNEL_C_DEL_MONITOR_NET = 3;   // user -> kernel: remove uid
    protected static final short REKERNEL_A_MSG = 1;
    protected static final short REKERNEL_A_UID = 2;

    protected static volatile int familyId = -1;       // genl family id ("rekernel")
    protected static volatile int mcastGroupId = -1;    // genl multicast group id ("events")

    protected static int align4(int n) {
        return (n + 3) & ~3;
    }

    protected static void closeAndSignalBlockedThreads(FileDescriptor fd) throws IOException {
        if (fd == null) {
            return;
        }
        try {
            Os.close(fd);
        } catch (ErrnoException errnoException) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                throw errnoException.rethrowAsIOException();
            } else {
                IOException exception = new IOException(errnoException.getMessage());
                exception.initCause(errnoException);
                throw exception;
            }
        }
    }

    protected static boolean resolveFamily(FileDescriptor descriptor) {
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

    protected static boolean parseFamilyReply(ByteBuffer byteBuffer, int length) {
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

    protected static int parseMcastGroups(ByteBuffer byteBuffer, int start, int end) {
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

    protected static String extractEvent(ByteBuffer byteBuffer, int length) {
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

    protected static int StringToInteger(String str) {
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

    protected static String readString(ByteBuffer byteBuffer, int dataPos, int dataLen) {
        int strLen = dataLen;
        while (strLen > 0 && byteBuffer.get(dataPos + strLen - 1) == 0)
            strLen--;
        byte[] out = new byte[strLen];
        for (int i = 0; i < strLen; i++)
            out[i] = byteBuffer.get(dataPos + i);
        return new String(out, StandardCharsets.UTF_8);
    }
}
