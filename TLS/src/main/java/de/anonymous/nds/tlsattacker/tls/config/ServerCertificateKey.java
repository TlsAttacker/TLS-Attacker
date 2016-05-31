/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config;

import anonymous.tlsattacker.tls.constants.CipherSuite;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public enum ServerCertificateKey {

    EC,
    DH,
    RSA,
    NONE;

    public static ServerCertificateKey getServerCertificateKey(CipherSuite cipherSuite) {
	String cipher = cipherSuite.toString().toUpperCase();
	if (cipher.startsWith("TLS_RSA") || cipher.matches("^TLS_[A-Z]+_RSA.+")) {
	    return RSA;
	} else if (cipher.matches("^TLS_[A-Z]+_DSS.+")) {
	    return DH;
	} else if (cipher.matches("^TLS_[A-Z]+_ECDSA.+")) {
	    return EC;
	} else {
	    return NONE;
	}
    }
}
