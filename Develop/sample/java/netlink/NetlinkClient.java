package nep.timeline.freezer.core.kernel.netlink;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructTimeval;

import java.io.Closeable;
import java.io.FileDescriptor;
import java.io.InterruptedIOException;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import nep.timeline.freezer.core.log.Log;

public class NetlinkClient implements Closeable {
    private static final String TAG = "NetlinkSocket";
    private static final int SOCKET_RECV_BUFSIZE = 64 * 1024;
    private static final int DEFAULT_RECV_BUFSIZE = 8 * 1024;
    final private FileDescriptor mDescriptor;
    private NetlinkSocketAddress mAddr;
    private long mLastRecvTimeoutMs;
    private long mLastSendTimeoutMs;

    public FileDescriptor getmDescriptor() {
        return mDescriptor;
    }

    public NetlinkClient(int nlProto) throws ErrnoException {
        mDescriptor = Os.socket(
                OsConstants.AF_NETLINK, OsConstants.SOCK_DGRAM, nlProto);
        IoUtils.setsockoptInt(
                mDescriptor, OsConstants.SOL_SOCKET,
                OsConstants.SO_RCVBUF, SOCKET_RECV_BUFSIZE);
    }

    public NetlinkSocketAddress getLocalAddress() throws ErrnoException {
        return (NetlinkSocketAddress) Os.getsockname(mDescriptor);
    }
    public void bind(NetlinkSocketAddress localAddr) throws ErrnoException, SocketException {
        Os.bind(mDescriptor, localAddr);
    }
    public void bind(SocketAddress localAddr) throws ErrnoException, SocketException {
        Os.bind(mDescriptor, localAddr);
    }
    public void connectTo(NetlinkSocketAddress peerAddr)
            throws ErrnoException, SocketException {
        Os.connect(mDescriptor, peerAddr);
    }
    public void connectToKernel() throws ErrnoException, SocketException {
        connectTo(new NetlinkSocketAddress(0, 0));
    }
    /**
     * Wait indefinitely (or until underlying socket error) for a
     * netlink message of at most DEFAULT_RECV_BUFSIZE size.
     */
    public ByteBuffer recvMessage()
            throws ErrnoException, InterruptedIOException {
        return recvMessage(DEFAULT_RECV_BUFSIZE, 0);
    }
    /**
     * Wait up to |timeoutMs| (or until underlying socket error) for a
     * netlink message of at most DEFAULT_RECV_BUFSIZE size.
     */
    public ByteBuffer recvMessage(long timeoutMs) throws ErrnoException, InterruptedIOException {
        return recvMessage(DEFAULT_RECV_BUFSIZE, timeoutMs);
    }
    private void checkTimeout(long timeoutMs) {
        if (timeoutMs < 0) {
            throw new IllegalArgumentException("Negative timeouts not permitted");
        }
    }
    /**
     * Wait up to |timeoutMs| (or until underlying socket error) for a
     * netlink message of at most |bufsize| size.
     *
     * Multi-threaded calls with different timeouts will cause unexpected results.
     */
    public ByteBuffer recvMessage(int bufsize, long timeoutMs)
            throws ErrnoException, IllegalArgumentException, InterruptedIOException {
        checkTimeout(timeoutMs);
        synchronized (mDescriptor) {
            if (mLastRecvTimeoutMs != timeoutMs) {
                Os.setsockoptTimeval(mDescriptor,
                        OsConstants.SOL_SOCKET, OsConstants.SO_RCVTIMEO,
                        StructTimeval.fromMillis(timeoutMs));
                mLastRecvTimeoutMs = timeoutMs;
            }
        }
        ByteBuffer byteBuffer = ByteBuffer.allocate(bufsize);
        int length = Os.read(mDescriptor, byteBuffer);
        if (length == bufsize) {
            Log.w("maximum read");
        }
        byteBuffer.position(0);
        byteBuffer.limit(length);
        byteBuffer.order(ByteOrder.nativeOrder());
        return byteBuffer;
    }

    /**
     * Send a message to a peer to which this socket has previously connected.
     *
     * This blocks until completion or an error occurs.
     */
    public boolean sendMessage(byte[] bytes, int offset, int count)
            throws ErrnoException, InterruptedIOException {
        return sendMessage(bytes, offset, count, 0);
    }
    /**
     * Send a message to a peer to which this socket has previously connected,
     * waiting at most |timeoutMs| milliseconds for the send to complete.
     *
     * Multi-threaded calls with different timeouts will cause unexpected results.
     */
    public boolean sendMessage(byte[] bytes, int offset, int count, long timeoutMs)
            throws ErrnoException, IllegalArgumentException, InterruptedIOException {
        checkTimeout(timeoutMs);
        synchronized (mDescriptor) {
            if (mLastSendTimeoutMs != timeoutMs) {
                Os.setsockoptTimeval(mDescriptor,
                        OsConstants.SOL_SOCKET, OsConstants.SO_SNDTIMEO,
                        StructTimeval.fromMillis(timeoutMs));
                mLastSendTimeoutMs = timeoutMs;
            }
        }
        return (count == Os.write(mDescriptor, bytes, offset, count));
    }

    @Override
    public void close() {
        IoUtils.closeQuietly(mDescriptor);
    }
}
