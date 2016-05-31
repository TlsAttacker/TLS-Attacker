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
public enum HashAlgorithm {

    NONE((byte) 0, ""),
    MD5((byte) 1, "MD5"),
    SHA1((byte) 2, "SHA-1"),
    SHA224((byte) 3, "SHA-224"),
    SHA256((byte) 4, "SHA-256"),
    SHA384((byte) 5, "SHA-384"),
    SHA512((byte) 6, "SHA-512");

    private final byte value;

    private final String javaName;

    private static final Map<Byte, HashAlgorithm> MAP;

    private HashAlgorithm(byte value, String javaName) {
	this.value = value;
	this.javaName = javaName;
    }

    static {
	MAP = new HashMap<>();
	for (HashAlgorithm cm : HashAlgorithm.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static HashAlgorithm getHashAlgorithm(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }

    public String getJavaName() {
	return javaName;
    }
}
