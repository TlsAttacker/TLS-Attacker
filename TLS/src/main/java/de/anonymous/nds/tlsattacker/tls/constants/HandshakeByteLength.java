/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.constants;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class HandshakeByteLength {

    /**
     * certificate length field
     */
    public static final int CERTIFICATE_LENGTH = 3;

    /**
     * certificates length field (certificate array can include several
     * certificates)
     */
    public static final int CERTIFICATES_LENGTH = 3;

    /**
     * cipher suite byte length
     */
    public static final int CIPHER_SUITE = 2;

    /**
     * compression length
     */
    public static final int COMPRESSION = 1;

    /**
     * message type length
     */
    public static final int MESSAGE_TYPE = 1;

    /**
     * length of the length field included in this message type
     */
    public static final int MESSAGE_TYPE_LENGTH = 3;

    /**
     * random length
     */
    public static final int RANDOM = 28;

    /**
     * length of the session id length field indicating the session id length
     */
    public static final int SESSION_ID_LENGTH = 1;

    /**
     * unix time byte length
     */
    public static final int UNIX_TIME = 4;

    /**
     * Premaster Secret
     */
    public static final int PREMASTER_SECRET = 48;

    /**
     * Length of the length field for the encrypted Premaster Secret
     */
    public static final int ENCRYPTED_PREMASTER_SECRET_LENGTH = 2;

    /**
     * Master Secret
     */
    public static final int MASTER_SECRET = 48;

    /**
     * Verify data from the finished message
     */
    public static final int VERIFY_DATA = 12;

    /**
     * Length of the signature length field
     */
    public static final int SIGNATURE_LENGTH = 2;

    /**
     * DH param length
     */
    public static final int DH_PARAM_LENGTH = 2;

    /**
     * Length of the signature hash algorithms length field
     */
    public static final int SIGNATURE_HASH_ALGORITHMS_LENGTH = 2;

    /**
     * Length of the distinguished names length field
     */
    public static final int DISTINGUISHED_NAMES_LENGTH = 2;

    /**
     * Length of the cookie field in DTLS ClientHello and ClientHelloVerify
     * messages.
     */
    public static final int DTLS_HANDSHAKE_COOKIE_LENGTH = 1;

}
