/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.ec.oracles;

import anonymous.tlsattacker.attacks.ec.oracles.ECOracle;
import anonymous.tlsattacker.tls.crypto.ec.Curve;
import anonymous.tlsattacker.tls.crypto.ec.CurveFactory;
import anonymous.tlsattacker.tls.crypto.ec.DivisionException;
import anonymous.tlsattacker.tls.crypto.ec.ECComputer;
import anonymous.tlsattacker.tls.crypto.ec.Point;
import java.math.BigInteger;
import java.util.Random;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class TestECOracle extends ECOracle {

    private final ECComputer computer;

    public TestECOracle(String namedCurve) {
	curve = CurveFactory.getNamedCurve(namedCurve);
	BigInteger privateKey = new BigInteger(curve.getKeyBits(), new Random());
	computer = new ECComputer(curve, privateKey);
    }

    @Override
    public boolean checkSecretCorrectnes(Point ecPoint, BigInteger guessedSecret) {
	numberOfQueries++;
	if (numberOfQueries % 100 == 0) {
	    LOGGER.info("Number of queries so far: {}", numberOfQueries);
	}
	Point result;
	try {
	    result = computer.mul(ecPoint, true);
	} catch (DivisionException ex) {
	    result = null;
	}

	if (result == null || result.isInfinity()) {
	    return false;
	} else {
	    return (result.getX().compareTo(guessedSecret) == 0);
	}
    }

    public ECComputer getComputer() {
	return computer;
    }

    @Override
    public boolean isFinalSolutionCorrect(BigInteger guessedSecret) {
	if (guessedSecret.equals(computer.getSecret())) {
	    return true;
	} else {
	    return false;
	}
    }
}
