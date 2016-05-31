/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.misc;

import java.lang.reflect.Field;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/**
 * If you run on an Oracle Java platform, it is possible that strong algorithms
 * are not allowed. In this case, you have to install a so called Unlimited
 * Strength Jurisdiction Policy.
 * 
 * We try to remove this limitation programmatically (see the field setters),
 * but it is possible that this does not work on all platforms.
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class UnlimitedStrengthTest {

    final Logger logger = LogManager.getLogger(UnlimitedStrengthTest.class);

    @Test
    public void testAES256() throws Exception {
	try {
	    Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
	    field.setAccessible(true);
	    field.set(null, java.lang.Boolean.FALSE);

	    Cipher encryptCipher = Cipher.getInstance("AES/CBC/NoPadding", new BouncyCastleProvider());
	    IvParameterSpec encryptIv = new IvParameterSpec(new byte[16]);
	    SecretKey encryptKey = new SecretKeySpec(new byte[32], "AES");
	    encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIv);
	} catch (InvalidKeyException ex) {
	    logger.warn("AES256 is probably not supported, you have to install Java Cryptography "
		    + "Extension (JCE) Unlimited Strength Jurisdiction Policy Files.");
	}
    }
}
