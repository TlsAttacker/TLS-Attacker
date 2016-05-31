/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.exceptions;

import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;

/**
 * Invalid message type exception (thrown when unexpected TLS message appears
 * during the TLS workflow)
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class InvalidMessageTypeException extends RuntimeException {

    public InvalidMessageTypeException() {
	super();
    }

    public InvalidMessageTypeException(String message) {
	super(message);
    }

    public InvalidMessageTypeException(ProtocolMessageType protocolMessageType) {
	super("This is not a " + protocolMessageType + " message");
    }

    public InvalidMessageTypeException(HandshakeMessageType handshakeMessageType) {
	super("This is not a " + handshakeMessageType + " message");
    }
}
