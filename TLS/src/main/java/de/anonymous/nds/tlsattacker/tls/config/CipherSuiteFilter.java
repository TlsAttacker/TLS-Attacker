/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config;

import anonymous.tlsattacker.tls.constants.AlgorithmResolver;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import java.util.List;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class CipherSuiteFilter {

    /**
     * CipherSuite filtering based on the key exchange method and on the
     * ephemeral property. This method is useful for establishing new workflows.
     * 
     * @param cipherSuites
     */
    public static void filterCipherSuites(List<CipherSuite> cipherSuites) {
	KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuites.get(0));
	boolean ephemeral = cipherSuites.get(0).isEphemeral();
	for (int i = cipherSuites.size() - 1; i > 0; i--) {
	    CipherSuite cs = cipherSuites.get(i);
	    if (AlgorithmResolver.getKeyExchangeAlgorithm(cs) != algorithm || cs.isEphemeral() != ephemeral) {
		cipherSuites.remove(i);
	    }
	}
    }
}
