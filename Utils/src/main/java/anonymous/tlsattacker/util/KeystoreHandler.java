/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class KeystoreHandler {

    public static KeyStore loadKeyStore(final String keyStorePath, final String keyStorePassword)
	    throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
	KeyStore ks = KeyStore.getInstance("JKS");
	ks.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());

	return ks;
    }
}
