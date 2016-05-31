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
public enum PRFAlgorithm {

    TLS_PRF_LEGACY(MacAlgorithm.NULL),
    TLS_PRF_SHA256(MacAlgorithm.HMAC_SHA256),
    TLS_PRF_SHA384(MacAlgorithm.HMAC_SHA384);

    private PRFAlgorithm(MacAlgorithm macAlgorithm) {
	this.macAlgorithm = macAlgorithm;
    }

    private final MacAlgorithm macAlgorithm;

    public MacAlgorithm getMacAlgorithm() {
	return macAlgorithm;
    }
}
