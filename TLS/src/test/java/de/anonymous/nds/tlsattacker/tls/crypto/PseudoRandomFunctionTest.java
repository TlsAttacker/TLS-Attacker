/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.crypto;

import anonymous.tlsattacker.tls.constants.PRFAlgorithm;
import java.util.Random;
import mockit.Mocked;
import mockit.NonStrictExpectations;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class PseudoRandomFunctionTest {

    public PseudoRandomFunctionTest() {
    }

    /**
     * Test of compute method, of class PseudoRandomFunction.
     * 
     * @param mockedTlsContext
     * @param mockedParameters
     */
    @Test
    public void testComputeForTls12(@Mocked final TlsContext mockedTlsContext,
	    @Mocked final SecurityParameters mockedParameters) {
	// Record expectations if/as needed:
	new NonStrictExpectations() {
	    {
		mockedTlsContext.getServerVersion();
		result = ProtocolVersion.TLSv12;
	    }
	    {
		mockedTlsContext.getSecurityParameters();
		result = mockedParameters;
	    }
	    {
		mockedParameters.getPrfAlgorithm();
		result = 1;
	    }
	};

	byte[] secret = new byte[48];
	String label = "master secret";
	byte[] seed = new byte[60];
	Random r = new Random();
	r.nextBytes(seed);
	int size = 48;

	byte[] result1 = TlsUtils.PRF(mockedTlsContext, secret, label, seed, size);
	byte[] result2 = PseudoRandomFunction.compute(PRFAlgorithm.TLS_PRF_SHA256, secret, label, seed, size);

	assertArrayEquals(result1, result2);

	new NonStrictExpectations() {
	    {
		mockedParameters.getPrfAlgorithm();
		result = 2;
	    }
	};

	result1 = TlsUtils.PRF(mockedTlsContext, secret, label, seed, size);
	result2 = PseudoRandomFunction.compute(PRFAlgorithm.TLS_PRF_SHA384, secret, label, seed, size);

	assertArrayEquals(result1, result2);
    }

    /**
     * Test of compute method, of class PseudoRandomFunction.
     */
    @Test
    public void testComputeForTls11() {
	byte[] secret = new byte[48];
	String label = "master secret";
	byte[] seed = new byte[60];
	Random r = new Random();
	r.nextBytes(seed);
	int size = 48;

	byte[] result1 = TlsUtils.PRF_legacy(secret, label, seed, size);

	byte[] result2 = PseudoRandomFunction.compute(PRFAlgorithm.TLS_PRF_LEGACY, secret, label, seed, size);

	assertArrayEquals(result1, result2);
    }
}
