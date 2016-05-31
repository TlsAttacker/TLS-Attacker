/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.crypto;

import anonymous.tlsattacker.tls.constants.PRFAlgorithm;
import anonymous.tlsattacker.tls.exceptions.CryptoException;
import anonymous.tlsattacker.util.ArrayConverter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.tls.TlsUtils;

/**
 * Pseudo random function computation for TLS 1.0 - 1.2 (for TLS 1.0, bouncy
 * castle TlsUtils are used)
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public final class PseudoRandomFunction {

    /** master secret label */
    public static final String MASTER_SECRET_LABEL = "master secret";

    /** client finished label */
    public static final String CLIENT_FINISHED_LABEL = "client finished";

    /** server finished label */
    public static final String SERVER_FINISHED_LABEL = "server finished";

    /** key expansion label */
    public static final String KEY_EXPANSION_LABEL = "key expansion";

    private PseudoRandomFunction() {

    }

    /**
     * Computes PRF output of the provided size using the given mac algorithm
     * 
     * @param prfAlgorithm
     * @param secret
     * @param label
     * @param seed
     * @param size
     * @return
     */
    public static byte[] compute(PRFAlgorithm prfAlgorithm, byte[] secret, String label, byte[] seed, int size) {

	switch (prfAlgorithm) {
	    case TLS_PRF_SHA256:
	    case TLS_PRF_SHA384:
		return computeTls12(secret, label, seed, size, prfAlgorithm.getMacAlgorithm().getJavaName());
	    case TLS_PRF_LEGACY:
		// prf legacy is the prf computation function for older protocol
		// versions, it works by default with sha1 and md5
		return TlsUtils.PRF_legacy(secret, label, seed, size);
	    default:
		throw new UnsupportedOperationException("PRF computation for different"
			+ " protocol versions is not supported yet");
	}
    }

    /**
     * PRF computation for TLS 1.2
     * 
     * @param secret
     * @param label
     * @param seed
     * @param size
     * @param macAlgorithm
     * @return
     */
    private static byte[] computeTls12(byte[] secret, String label, byte[] seed, int size, String macAlgorithm) {
	try {
	    byte[] labelSeed = ArrayConverter.concatenate(label.getBytes(), seed);

	    SecretKeySpec keySpec = new SecretKeySpec(secret, macAlgorithm);
	    Mac mac = Mac.getInstance(macAlgorithm);
	    mac.init(keySpec);

	    byte[] out = new byte[0];

	    byte[] ai = labelSeed;
	    byte[] buf;
	    byte[] buf2;
	    while (out.length < size) {
		mac.update(ai);
		buf = mac.doFinal();
		ai = buf;
		mac.update(ai);
		mac.update(labelSeed);
		buf2 = mac.doFinal();
		out = ArrayConverter.concatenate(out, buf2);
	    }
	    return Arrays.copyOf(out, size);
	} catch (NoSuchAlgorithmException | InvalidKeyException ex) {
	    throw new CryptoException(ex);
	}
    }
}
