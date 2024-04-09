package nep.timeline.freezer.core.kernel;

import android.system.ErrnoException;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import nep.timeline.freezer.core.kernel.netlink.NetlinkClient;
import nep.timeline.freezer.core.kernel.netlink.NetlinkSocketAddress;
import nep.timeline.freezer.core.log.Log;
import nep.timeline.freezer.core.utils.StringUtils;

public class ReKernel {
    private static boolean isRunning = false;

    // You should create a new thread to invoke this method
    public static void start() {
        if (isRunning)
            return;

        try {
            int proto = StringUtils.StringToInteger(FileUtils.readFileToString(new File("/proc/rekernel", "rekernel_unit"), StandardCharsets.UTF_8));
            NetlinkClient netlinkClient = new NetlinkClient(proto);
            if (!netlinkClient.getmDescriptor().valid()) {
                BinderHelper.start();
                return;
            }

            netlinkClient.bind((SocketAddress) new NetlinkSocketAddress(100).toInstance());

            isRunning = true;

            Log.i("Connected to Re:Kernel!");

            while (true) {
                try {
                    ByteBuffer byteBuffer = netlinkClient.recvMessage();
                    String data = new String(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit(), StandardCharsets.UTF_8);
                    if (!data.isEmpty()) {
                        String type = StringUtils.getSubString(data, "type=", ",").trim();
                        if (type.equals("Binder")) {
                            String bindertype = StringUtils.getSubString(data, "bindertype=", ",").trim();
                            int oneway = StringUtils.StringToInteger(StringUtils.getSubString(data, "oneway=", ","));
                            int fromUid = StringUtils.StringToInteger(StringUtils.getSubString(data, "from=", ","));
                            int targetUid = StringUtils.StringToInteger(StringUtils.getSubString(data, "target=", ";"));
                            if (oneway == 0 || bindertype.equals("free_buffer_full")) {
                                // Your code
                            }
                        } else if (type.equals("Signal")) {
                            int targetPid = StringUtils.StringToInteger(StringUtils.getSubString(data, "dst_pid=", ","));
                            int targetUid = StringUtils.StringToInteger(StringUtils.getSubString(data, "dst=", ";"));
                            // Your code
                        }
                    }
                } catch (ErrnoException | InterruptedIOException | NumberFormatException ignored) {

                } catch (Exception e) {
                    Log.e(e);
                }
            }
        } catch (ErrnoException | SocketException e) {
            if (!isRunning)
                BinderHelper.start();
            Log.e(e);
        }
    }
}
