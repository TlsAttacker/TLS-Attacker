/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tlsserver;

import java.security.KeyPair;
import java.security.KeyStore;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class KeyStoreGeneratorTest {

    public KeyStoreGeneratorTest() {
    }

    /**
     * Test of createRSAKeyPair method, of class KeyStoreGenerator.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testCreateRSAKeyPair() throws Exception {
	KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024);
	assertNotNull(k);
	assertEquals("RSA", k.getPublic().getAlgorithm());
    }

    /**
     * Test of createECKeyPair method, of class KeyStoreGenerator.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testCreateECKeyPair() throws Exception {
	KeyPair k = KeyStoreGenerator.createECKeyPair(256);
	assertNotNull(k);
	assertEquals("EC", k.getPublic().getAlgorithm());
    }

    /**
     * Test of createKeyStore method, of class KeyStoreGenerator.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testCreateKeyStore() throws Exception {
	KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024);
	KeyStore ks = KeyStoreGenerator.createKeyStore(k);
	assertNotNull(ks);

	k = KeyStoreGenerator.createECKeyPair(256);
	ks = KeyStoreGenerator.createKeyStore(k);
	assertNotNull(ks);
    }

}
