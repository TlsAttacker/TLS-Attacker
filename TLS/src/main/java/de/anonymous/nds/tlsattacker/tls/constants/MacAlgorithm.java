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
public enum MacAlgorithm {

    NULL("null"),
    AEAD("null"),
    HMAC_MD5("HmacMD5"),
    HMAC_SHA1("HmacSHA1"),
    HMAC_SHA256("HmacSHA256"),
    HMAC_SHA384("HmacSHA384"),
    HMAC_SHA512("HmacSHA512");

    MacAlgorithm(String javaName) {
	this.javaName = javaName;
    }

    private final String javaName;

    public String getJavaName() {
	return javaName;
    }
}
