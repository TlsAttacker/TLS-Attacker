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
public enum DigestAlgorithm {

    LEGACY(""),
    SHA256("SHA-256"),
    SHA384("SHA-384");

    private DigestAlgorithm(String digestAlgorithm) {
	this.javaName = digestAlgorithm;
    }

    private final String javaName;

    public String getJavaName() {
	return javaName;
    }
}
