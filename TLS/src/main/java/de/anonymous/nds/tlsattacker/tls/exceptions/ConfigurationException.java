/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.exceptions;

/**
 * Configuration exception
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ConfigurationException extends RuntimeException {

    public ConfigurationException() {
	super();
    }

    public ConfigurationException(String message) {
	super(message);
    }

    public ConfigurationException(String message, Throwable cause) {
	super(message, cause);
    }
}
