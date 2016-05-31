/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.exceptions;

/**
 * Thrown when problems by in the TLS workflow appear.
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class WorkflowExecutionException extends RuntimeException {

    public WorkflowExecutionException() {
	super();
    }

    public WorkflowExecutionException(String message) {
	super(message);
    }

    public WorkflowExecutionException(String message, Throwable t) {
	super(message, t);
    }
}
