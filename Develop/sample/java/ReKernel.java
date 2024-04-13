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
            // Additionally, developers can create a new value in the configuration file for users to fill in the unit themselves
            File dir = new File("/proc/rekernel");
            while (!dir.exists());
            File[] files = dir.listFiles();
            while (files == null) {
                files = dir.listFiles();
            }
            File file = files[0];
            int netlinkUnit = StringUtils.StringToInteger(file.getName());
            NetlinkClient netlinkClient = new NetlinkClient(netlinkUnit);
            while (!netlinkClient.getmDescriptor().valid())
                netlinkClient = new NetlinkClient(netlinkUnit);

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
                            int fromPid = StringUtils.StringToInteger(StringUtils.getSubString(data, "from_pid=", ","));
                            int fromUid = StringUtils.StringToInteger(StringUtils.getSubString(data, "from=", ","));
                            int targetPid = StringUtils.StringToInteger(StringUtils.getSubString(data, "target_pid=", ","));
                            int targetUid = StringUtils.StringToInteger(StringUtils.getSubString(data, "target=", ";"));
                            if (oneway == 0 || bindertype.equals("free_buffer_full")) {
                                // Your code
                            }
                        } else if (type.equals("Signal")) {
                            int killerPid = StringUtils.StringToInteger(StringUtils.getSubString(data, "killer_pid=", ","));
                            int killerUid = StringUtils.StringToInteger(StringUtils.getSubString(data, "killer=", ","));
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
