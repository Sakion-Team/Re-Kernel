package nep.timeline.freezer.core.kernel.netlink;

import java.net.SocketAddress;
import java.util.Objects;

import de.robv.android.xposed.XposedHelpers;

public final class NetlinkSocketAddress extends SocketAddress {
    /**
     * port ID
     *
     * @hide
     */
    private final int nlPortId;

    /**
     * multicast groups mask
     *
     * @hide
     */
    private final int nlGroupsMask;

    /**
     * @hide
     */
    // VisibleForTesting
    public NetlinkSocketAddress() {
        this(0, 0);
    }
    /**
     * @hide
     */
    // VisibleForTesting
    public NetlinkSocketAddress(int nlPortId) {
        this(nlPortId, 0);
    }

    /**
     * Constructs an instance with the given port id and groups mask.
     *
     * @param nlPortId     port id
     * @param nlGroupsMask groups mask
     *
     * @hide
     */
    public NetlinkSocketAddress(int nlPortId, int nlGroupsMask) {
        this.nlPortId = nlPortId;
        this.nlGroupsMask = nlGroupsMask;
    }

    /**
     * Returns this address's port id.
     *
     * @return port id
     *
     * @hide
     */
    public int getPortId() {
        return nlPortId;
    }

    /**
     * Returns this address's groups multicast mask.
     *
     * @return groups mask
     *
     * @hide
     */
    public int getGroupsMask() {
        return nlGroupsMask;
    }

    /**
     * @hide
     */
    @Override public String toString() {
        return Objects.toString(this);
    }

    public Object toInstance() {
        return XposedHelpers.newInstance(XposedHelpers.findClass("android.system.NetlinkSocketAddress", IoUtils.classLoader), nlPortId, nlGroupsMask);
    }
}
