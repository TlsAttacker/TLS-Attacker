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
public enum SignatureAlgorithm {

    ANONYMOUS((byte) 0),
    RSA((byte) 1),
    DSA((byte) 2),
    ECDSA((byte) 3);

    private byte value;

    private static final Map<Byte, SignatureAlgorithm> MAP;

    private SignatureAlgorithm(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (SignatureAlgorithm cm : SignatureAlgorithm.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static SignatureAlgorithm getSignatureAlgorithm(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }

    public String getJavaName() {
	if (value == 0) {
	    return "";
	}
	return toString();
    }
}
