/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.crypto.ec;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class DivisionException extends Exception {

    private int round;

    public DivisionException(String message) {
	super(message);
    }

    public DivisionException(String message, int i) {
	super(message + " Error happend in round " + i);
	round = i;
    }

    public int getRound() {
	return round;
    }
}
