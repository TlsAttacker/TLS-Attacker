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
 * Name Type for Server Name Indication
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public enum NameType {

    HOST_NAME((byte) 0);

    private byte value;

    private static final Map<Byte, NameType> MAP;

    private NameType(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (NameType cm : NameType.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static NameType getNameType(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }
}
