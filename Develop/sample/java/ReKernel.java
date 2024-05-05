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
    public static boolean received = false;
    private static final int NETLINK_UNIT_DEFAULT = 22;

    // You should create a new thread to invoke this method
    public static void start() {
        if (isRunning)
            return;

        try {
            int netlinkUnit;
            File file = new File(FreezerConfig.ConfigDir, "netlink.unit");
            if (file.exists()) {
                String unit = FreezerConfig.getString("netlink.unit");
                if (unit.trim().isEmpty()) {
                    File dir = new File("/proc/rekernel");
                    if (dir.exists()) {
                        File[] files = dir.listFiles();
                        if (files == null) {
                            Log.e("Failed to find re:kernel unit");
                            return;
                        }
                        File unitFile = files[0];
                        netlinkUnit = StringUtils.StringToInteger(unitFile.getName());
                    } else netlinkUnit = NETLINK_UNIT_DEFAULT;
                } else {
                    netlinkUnit = StringUtils.StringToInteger(unit);
                }
            } else {
                File dir = new File("/proc/rekernel");
                if (dir.exists()) {
                    File[] files = dir.listFiles();
                    if (files == null) {
                        Log.e("Failed to find re:kernel unit");
                        return;
                    }
                    File unitFile = files[0];
                    netlinkUnit = StringUtils.StringToInteger(unitFile.getName());
                } else netlinkUnit = NETLINK_UNIT_DEFAULT;
            }

            NetlinkClient netlinkClient = new NetlinkClient(netlinkUnit);
            if (!netlinkClient.getmDescriptor().valid()) {
                Log.e("Failed to connect re:kernel server");
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
                        if (data.contains("type=") && !received) {
                            Log.i("Successfully received message from re:kernel");
                            received = true;
                        }
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
                        } else if (type.equals("Network")) {
                            int targetUid = StringUtils.StringToInteger(StringUtils.getSubString(data, "target=", ";"));
                            // Your code
                        }
                    }
                } catch (ErrnoException | InterruptedIOException | NumberFormatException ignored) {

                } catch (Exception e) {
                    Log.e(e);
                }
            }
        } catch (ErrnoException | SocketException e) {
            Log.e("Failed to connect re:kernel server");
        }
    }
}
