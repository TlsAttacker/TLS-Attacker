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
public class ServerHelloDoneMessage extends HandshakeMessage {

    public ServerHelloDoneMessage() {
	super(HandshakeMessageType.SERVER_HELLO_DONE);
	this.messageIssuer = ConnectionEnd.SERVER;
    }

    public ServerHelloDoneMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.SERVER_HELLO_DONE);
	this.messageIssuer = messageIssuer;
    }
}
