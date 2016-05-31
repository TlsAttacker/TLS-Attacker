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
 * Alert level
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public enum AlertLevel {

    WARNING((byte) 1),
    FATAL((byte) 2);

    private byte value;

    private static final Map<Byte, AlertLevel> MAP;

    private AlertLevel(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (AlertLevel cm : AlertLevel.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static AlertLevel getAlertLevel(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }
}
