package org.sakion.rekernel;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

final class NetlinkUtils {
    private NetlinkUtils() {}

    static final int NLMSG_HDRLEN = 16;      // struct nlmsghdr
    static final int GENL_HDRLEN  = 4;       // struct genlmsghdr
    static final int NLA_HDRLEN   = 4;       // struct nlattr
    static final int NLA_TYPE_MASK = 0x3FFF; // strip NLA_F_NESTED / NLA_F_NET_BYTEORDER

    static int align4(int n) {
        return (n + 3) & ~3;
    }

    // ---- writers ----

    /** Exact-size, native-order buffer. {@code total} must equal the final nlmsg_len. */
    static ByteBuffer nlBuf(int total) {
        return ByteBuffer.wrap(new byte[total]).order(ByteOrder.nativeOrder());
    }

    static void putNlMsgHdr(ByteBuffer b, int len, int type, int flags, int seq, int pid) {
        b.putInt(len);
        b.putShort((short) type);
        b.putShort((short) flags);
        b.putInt(seq);
        b.putInt(pid);
    }

    static void putGenlHdr(ByteBuffer b, int cmd, int version) {
        b.put((byte) cmd);
        b.put((byte) version);
        b.putShort((short) 0);
    }

    /** Fixed 8-byte u32 attribute; already 4-aligned so no trailing padding. */
    static void putAttrU32(ByteBuffer b, int type, int value) {
        b.putShort((short) (NLA_HDRLEN + 4));
        b.putShort((short) type);
        b.putInt(value);
    }

    /** Variable attribute. nla_len carries the UNPADDED length; padding to the
     *  next 4-byte boundary is written separately (and is part of nlmsg_len). */
    static void putAttrBytes(ByteBuffer b, int type, byte[] payload) {
        b.putShort((short) (NLA_HDRLEN + payload.length));
        b.putShort((short) type);
        b.put(payload);
        for (int i = payload.length; i < align4(payload.length); i++)
            b.put((byte) 0);
    }

    /** Decode a netlink string attribute, trimming trailing NULs. */
    static String readString(ByteBuffer b, int dataPos, int dataLen) {
        int n = dataLen;
        while (n > 0 && b.get(dataPos + n - 1) == 0)
            n--;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++)
            out[i] = b.get(dataPos + i);
        return new String(out, StandardCharsets.UTF_8);
    }

    // ---- reader ----

    /**
     * Forward cursor over a run of {@code struct nlattr} TLVs in {@code [start, end)}.
     * After {@link #next()} returns true, {@link #type}/{@link #dataPos}/{@link #dataLen}
     * describe the current attribute. {@code type} is masked with {@link #NLA_TYPE_MASK}.
     */
    static final class AttrCursor {
        int type, dataPos, dataLen;

        private final ByteBuffer b;
        private final int end;
        private int pos;

        AttrCursor(ByteBuffer b, int start, int end) {
            this.b = b;
            this.pos = start;
            this.end = end;
        }

        boolean next() {
            if (pos + NLA_HDRLEN > end)
                return false;
            int len = b.getShort(pos) & 0xFFFF;
            if (len < NLA_HDRLEN)
                return false;
            type = b.getShort(pos + 2) & NLA_TYPE_MASK;
            dataPos = pos + NLA_HDRLEN;
            dataLen = len - NLA_HDRLEN;
            pos += align4(len);
            return true;
        }
    }
}
