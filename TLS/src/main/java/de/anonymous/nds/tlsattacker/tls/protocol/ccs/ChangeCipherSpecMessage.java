/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.ccs;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.ProtocolMessageHandler;
import anonymous.tlsattacker.tls.protocol.ccs.ChangeCipherSpecHandler;
import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.workflow.TlsContext;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ChangeCipherSpecMessage extends ProtocolMessage {

    @ModifiableVariableProperty
    ModifiableByte ccsProtocolType;

    public ChangeCipherSpecMessage() {
	this.protocolMessageType = ProtocolMessageType.CHANGE_CIPHER_SPEC;
    }

    public ChangeCipherSpecMessage(ConnectionEnd messageIssuer) {
	this();
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByte getCcsProtocolType() {
	return ccsProtocolType;
    }

    public void setCcsProtocolType(ModifiableByte ccsProtocolType) {
	this.ccsProtocolType = ccsProtocolType;
    }

    public void setCcsProtocolType(byte value) {
	this.ccsProtocolType = ModifiableVariableFactory.safelySetValue(ccsProtocolType, value);
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
	ChangeCipherSpecHandler ccsh = new ChangeCipherSpecHandler(tlsContext);
	ccsh.setProtocolMessage(this);
	return ccsh;
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\nChangeCipherSpec message:").append("\n  CCS Protocol Message: ")
		.append(String.format("%02X ", ccsProtocolType.getValue()));
	return sb.toString();
    }

    @Override
    public String toCompactString() {
	return "ChangeCipherSpec";
    }
}
