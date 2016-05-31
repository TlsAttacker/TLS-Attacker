/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.exceptions;

/**
 * @author anonymous Pfützenreuter <anonymous.pfuetzenreuter@anonymous>
 */
public class MalformedMessageException extends RuntimeException {

    public MalformedMessageException() {
	super();
    }

    public MalformedMessageException(String message) {
	super(message);
    }
}
