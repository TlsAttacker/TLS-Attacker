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
public enum HeartbeatMessageType {

    HEARTBEAT_REQUEST((byte) 1),
    HEARTBEAT_RESPONSE((byte) 2);

    private byte value;

    private static final Map<Byte, HeartbeatMessageType> MAP;

    private HeartbeatMessageType(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (HeartbeatMessageType cm : HeartbeatMessageType.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static HeartbeatMessageType getHeartbeatMessageType(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }
}
