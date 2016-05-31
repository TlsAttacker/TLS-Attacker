/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.pkcs1;

import anonymous.tlsattacker.attacks.pkcs1.oracles.Pkcs1Oracle;
import anonymous.tlsattacker.attacks.pkcs1.oracles.TestPkcs1Oracle;
import anonymous.tlsattacker.attacks.pkcs1.oracles.StdPlainPkcs1Oracle;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import org.apache.logging.log4j.LogManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class BleichenbacherAttackPlaintextTest {

    private static final int PREMASTER_SECRET_LENGTH = 48;

    @Test
    public final void testBleichenbacherAttack() throws Exception {

	Security.addProvider(new BouncyCastleProvider());
	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	keyPairGenerator.initialize(2048);
	KeyPair keyPair = keyPairGenerator.genKeyPair();

	SecureRandom sr = new SecureRandom();
	byte[] plainBytes = new byte[PREMASTER_SECRET_LENGTH];
	sr.nextBytes(plainBytes);
	byte[] cipherBytes;

	Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
	cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
	cipherBytes = cipher.doFinal(plainBytes);

	cipher = Cipher.getInstance("RSA/None/NoPadding");
	cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
	byte[] message = cipher.doFinal(cipherBytes);

	Pkcs1Oracle oracle = new StdPlainPkcs1Oracle(keyPair.getPublic(), TestPkcs1Oracle.OracleType.TTT,
		cipher.getBlockSize());

	Bleichenbacher attacker = new Bleichenbacher(message, oracle, true);
	attacker.attack();
	BigInteger solution = attacker.getSolution();

	Assert.assertArrayEquals("The computed solution for Bleichenbacher must be equal to the original message",
		message, solution.toByteArray());
    }
}
