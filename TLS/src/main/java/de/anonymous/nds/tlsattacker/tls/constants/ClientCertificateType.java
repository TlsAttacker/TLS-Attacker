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
 * http://tools.ietf.org/html/rfc5246#section-7.4.4
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public enum ClientCertificateType {

    RSA_SIGN((byte) 1),
    DSS_SIGN((byte) 2),
    RSA_FIXED_DH((byte) 3),
    DSS_FIXED_DH((byte) 4),
    RSA_EPHEMERAL_DH_RESERVED((byte) 5),
    DSS_EPHEMERAL_DH_RESERVED((byte) 6),
    FORTEZZA_DMS_RESERVED((byte) 20);

    /**
     * length of the ClientCertificateType in the TLS byte arrays
     */
    public static final int LENGTH = 1;

    private byte value;

    private static final Map<Byte, ClientCertificateType> MAP;

    private ClientCertificateType(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (ClientCertificateType c : ClientCertificateType.values()) {
	    MAP.put(c.value, c);
	}
    }

    public static ClientCertificateType getClientCertificateType(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }
}
