/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.pkcs1;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 * @version 0.1
 */
public class OracleException extends RuntimeException {

    public OracleException() {

    }

    public OracleException(String message) {
	super(message);
    }

    public OracleException(String message, Throwable t) {
	super(message, t);
    }

}
