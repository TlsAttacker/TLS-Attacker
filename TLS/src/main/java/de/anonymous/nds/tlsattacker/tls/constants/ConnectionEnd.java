/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.constants;

/**
 * Defines the connection end. Either client or server.
 * 
 * @author anonymous
 */
public enum ConnectionEnd {

    CLIENT,
    SERVER;

    public ConnectionEnd getPeer() {
	if (this == CLIENT) {
	    return SERVER;
	} else {
	    return CLIENT;
	}
    }

}
