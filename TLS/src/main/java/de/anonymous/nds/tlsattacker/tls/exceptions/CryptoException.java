/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.exceptions;

/**
 * Crypto exception
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class CryptoException extends RuntimeException {

    public CryptoException() {
	super();
    }

    public CryptoException(String message) {
	super(message);
    }

    public CryptoException(Throwable t) {
	super(t);
    }

    public CryptoException(String message, Throwable t) {
	super(message, t);
    }

}
