/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol;

import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.protocol.handshake.HandshakeMessage;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ProtocolMessageTypeHolder {

    private ProtocolMessageType protocolMessageType;

    private HandshakeMessageType handshakeMessageType;

    public ProtocolMessageTypeHolder(byte value) {
	this.protocolMessageType = ProtocolMessageType.getContentType(value);
    }

    public ProtocolMessageTypeHolder(ProtocolMessageType value) {
	this.protocolMessageType = value;
    }

    public ProtocolMessageTypeHolder(byte protocolMessageType, byte handshakeMessageType) {
	this.protocolMessageType = ProtocolMessageType.getContentType(protocolMessageType);
	this.handshakeMessageType = HandshakeMessageType.getMessageType(handshakeMessageType);
    }

    public ProtocolMessageTypeHolder(ProtocolMessageType protocolMessageType, HandshakeMessageType handshakeMessageType) {
	this.protocolMessageType = protocolMessageType;
	this.handshakeMessageType = handshakeMessageType;
    }

    public ProtocolMessageTypeHolder(ProtocolMessage protocolMessage) {
	this.protocolMessageType = protocolMessage.getProtocolMessageType();
	if (protocolMessage.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
	    this.handshakeMessageType = ((HandshakeMessage) protocolMessage).getHandshakeMessageType();
	}
    }

    public ProtocolMessageType getContentType() {
	return protocolMessageType;
    }

    public void setContentType(ProtocolMessageType contentType) {
	this.protocolMessageType = contentType;
    }

    public HandshakeMessageType getHandshakeMessageType() {
	return handshakeMessageType;
    }

    public void setHandshakeMessageType(HandshakeMessageType handshakeMessageType) {
	this.handshakeMessageType = handshakeMessageType;
    }

    @Override
    public boolean equals(Object obj) {
	if (obj == null) {
	    return false;
	}
	if (!(obj instanceof ProtocolMessageTypeHolder)) {
	    return false;
	}
	ProtocolMessageTypeHolder pmth = (ProtocolMessageTypeHolder) obj;
	return protocolMessageType == pmth.protocolMessageType && handshakeMessageType == pmth.handshakeMessageType;
    }

}
