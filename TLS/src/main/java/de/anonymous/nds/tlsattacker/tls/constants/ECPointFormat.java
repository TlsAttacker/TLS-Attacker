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
public enum ECPointFormat {

    UNCOMPRESSED((byte) 0),
    ANSIX962_COMPRESSED_PRIME((byte) 1),
    ANSIX962_COMPRESSED_CHAR2((byte) 2);

    private byte value;

    private static final Map<Byte, ECPointFormat> MAP;

    private ECPointFormat(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (ECPointFormat cm : ECPointFormat.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static ECPointFormat getECPointFormat(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }

    public short getShortValue() {
	return (short) (value & 0xFF);
    }
}
