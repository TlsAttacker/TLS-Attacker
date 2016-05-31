/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.exceptions;

/**
 * Thrown when problems by modification application appear.
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ModificationException extends RuntimeException {

    public ModificationException() {
	super();
    }

    public ModificationException(String message) {
	super(message);
    }

    public ModificationException(String message, Throwable cause) {
	super(message, cause);
    }
}
