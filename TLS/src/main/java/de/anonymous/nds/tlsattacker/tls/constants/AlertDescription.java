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
 * TLS Alerts
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public enum AlertDescription {

    CLOSE_NOTIFY((byte) 0),
    UNEXPECTED_MESSAGE((byte) 10),
    BAD_RECORD_MAC((byte) 20),
    DECRYPTION_FAILED_RESERVED((byte) 21),
    RECORD_OVERFLOW((byte) 22),
    DECOMPRESSION_FAILURE((byte) 30),
    HANDSHAKE_FAILURE((byte) 40),
    NO_CERTIFICATE_RESERVED((byte) 41),
    BAD_CERTIFICATE((byte) 42),
    UNSUPPORTED_CERTIFICATE((byte) 43),
    CERTIFICATE_REVOKED((byte) 44),
    CERTIFICATE_EXPIRED((byte) 45),
    CERTIFICATE_UNKNOWN((byte) 46),
    ILLEGAL_PARAMETER((byte) 47),
    UNKNOWN_CA((byte) 48),
    ACCESS_DENIED((byte) 49),
    DECODE_ERROR((byte) 50),
    DECRYPT_ERROR((byte) 51),
    EXPORT_RESTRICTION_RESERVED((byte) 60),
    PROTOCOL_VERSION((byte) 70),
    INSUFFICIENT_SECURITY((byte) 71),
    INTERNAL_ERROR((byte) 80),
    USER_CANCELED((byte) 90),
    NO_RENEGOTIATION((byte) 100),
    UNSUPPORTED_EXTENSION((byte) 110),
    CERTIFICATE_UNOBTAINABLE((byte) 111),
    UNRECOGNIZED_NAME((byte) 112),
    BAD_CERTIFICATE_STATUS_RESPONSE((byte) 113),
    BAD_CERTIFICATE_HASH_VALUE((byte) 114);

    private byte value;

    private static final Map<Byte, AlertDescription> MAP;

    private AlertDescription(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (AlertDescription cm : AlertDescription.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static AlertDescription getAlertDescription(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }
}
