/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.constants;

import java.util.HashMap;
import java.util.Map;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public enum HeartbeatMode {

    PEER_ALLOWED_TO_SEND((byte) 1),
    PEER_NOT_ALLOWED_TO_SEND((byte) 2);

    private byte value;

    private static final Map<Byte, HeartbeatMode> MAP;

    private HeartbeatMode(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (HeartbeatMode cm : HeartbeatMode.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static HeartbeatMode getHeartbeatMessageType(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }
}
