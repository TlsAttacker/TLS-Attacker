/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.pkcs1.oracles;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class StdPlainPkcs1Oracle extends TestPkcs1Oracle {

    public StdPlainPkcs1Oracle(final PublicKey pubKey, final TestPkcs1Oracle.OracleType oracleType, final int blockSize) {
	this.publicKey = (RSAPublicKey) pubKey;
	this.oracleType = oracleType;
	this.isPlaintextOracle = true;
	this.blockSize = blockSize;
    }

    @Override
    public boolean checkPKCSConformity(final byte[] msg) {
	numberOfQueries++;
	return checkDecryptedBytes(msg);
    }
}
