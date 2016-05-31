/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class HelloRequestMessage extends HandshakeMessage {

    public HelloRequestMessage() {
	super(HandshakeMessageType.HELLO_REQUEST);
	this.messageIssuer = ConnectionEnd.SERVER;
	setIncludeInDigest(false);
    }

    public HelloRequestMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.HELLO_REQUEST);
	this.messageIssuer = messageIssuer;
	setIncludeInDigest(false);
    }
}
