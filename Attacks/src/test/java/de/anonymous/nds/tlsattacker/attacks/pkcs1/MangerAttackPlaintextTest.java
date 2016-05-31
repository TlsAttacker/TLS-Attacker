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
import anonymous.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class MangerAttackPlaintextTest {

    private static final int PREMASTER_SECRET_LENGTH = 48;

    @Test
    public final void testMangerAttack() throws Exception {

	Security.addProvider(new BouncyCastleProvider());
	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	keyPairGenerator.initialize(2048);
	KeyPair keyPair = keyPairGenerator.genKeyPair();

	Random sr = new Random();
	byte[] plainBytes = new byte[PREMASTER_SECRET_LENGTH];
	sr.nextBytes(plainBytes);
	byte[] cipherBytes;

	Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
	cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
	cipherBytes = cipher.doFinal(plainBytes);

	cipher = Cipher.getInstance("RSA/None/NoPadding");
	cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
	byte[] message = cipher.doFinal(cipherBytes);

	Pkcs1Oracle oracle = new StdPlainPkcs1Oracle(keyPair.getPublic(), TestPkcs1Oracle.OracleType.MANGER_0x00,
		cipher.getBlockSize());

	// we are handling plaintexts, so we insert raw message there
	Manger attacker = new Manger(message, oracle);
	attacker.attack();
	BigInteger solution = attacker.getSolution();

	Assert.assertArrayEquals("The computed solution for Manger attack must be equal to the original message",
		message, solution.toByteArray());

	// test with a message not starting with 0x00
	message = ArrayConverter.concatenate(new byte[] { 1 }, message);
	System.out.println(ArrayConverter.bytesToHexString(message));
	attacker = new Manger(message, oracle);
	attacker.attack();
	solution = attacker.getSolution();

	Assert.assertArrayEquals("The computed solution for Manger attack must be equal to the original message",
		message, solution.toByteArray());
    }

    @Test
    @Ignore
    public final void testMangerAttackPerformance() throws Exception {

	Security.addProvider(new BouncyCastleProvider());
	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	keyPairGenerator.initialize(4096);
	KeyPair keyPair = keyPairGenerator.genKeyPair();

	List<Long> queries = new LinkedList<>();

	for (int i = 0; i < 100; i++) {
	    Random sr = new Random();
	    byte[] plainBytes = new byte[PREMASTER_SECRET_LENGTH];
	    sr.nextBytes(plainBytes);
	    byte[] cipherBytes;

	    Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
	    cipherBytes = cipher.doFinal(plainBytes);

	    cipher = Cipher.getInstance("RSA/None/NoPadding");
	    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
	    byte[] message = cipher.doFinal(cipherBytes);

	    Pkcs1Oracle oracle = new StdPlainPkcs1Oracle(keyPair.getPublic(), TestPkcs1Oracle.OracleType.MANGER_0x00,
		    cipher.getBlockSize());

	    // we are handling plaintexts, so we insert raw message there
	    Manger attacker = new Manger(message, oracle);
	    attacker.attack();
	    BigInteger solution = attacker.getSolution();

	    Assert.assertArrayEquals("The computed solution for Manger attack must be equal to the original message",
		    message, solution.toByteArray());

	    queries.add(oracle.getNumberOfQueries());
	}

	Collections.sort(queries);
	System.out.println(queries);
    }
}
