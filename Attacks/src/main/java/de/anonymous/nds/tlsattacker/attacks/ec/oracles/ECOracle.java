/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.ec.oracles;

import anonymous.tlsattacker.tls.crypto.ec.Curve;
import anonymous.tlsattacker.tls.crypto.ec.Point;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public abstract class ECOracle {

    /**
     * logger
     */
    static Logger LOGGER = LogManager.getLogger(ECOracle.class);

    /*
     * number of queries issued to oracle
     */
    long numberOfQueries;

    /** curve used by the oracle */
    Curve curve;

    /**
     * Takes an ec point and a guessed secret and returns true, in case the
     * secret was guessed correctly.
     * 
     * @param ecPoint
     * @param guessedSecret
     * @return
     */
    public abstract boolean checkSecretCorrectnes(Point ecPoint, BigInteger guessedSecret);

    /**
     * Sends the oracle a request with a guessed secret key resulting from the
     * attack. The oracle responds with true, in case the guessed key was
     * correct.
     * 
     * @param guessedSecret
     * @return
     */
    public abstract boolean isFinalSolutionCorrect(BigInteger guessedSecret);

    public long getNumberOfQueries() {
	return numberOfQueries;
    }

    public void setNumberOfQueries(long numberOfQueries) {
	this.numberOfQueries = numberOfQueries;
    }

    public Curve getCurve() {
	return curve;
    }

    public void setCurve(Curve curve) {
	this.curve = curve;
    }
}
