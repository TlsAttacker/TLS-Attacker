/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.application;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.ProtocolMessageHandler;
import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.workflow.TlsContext;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ApplicationMessage extends ProtocolMessage {

    @ModifiableVariableProperty
    ModifiableByteArray data;

    public ApplicationMessage() {
	this.protocolMessageType = ProtocolMessageType.APPLICATION_DATA;
    }

    public ApplicationMessage(ConnectionEnd messageIssuer) {
	this();
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByteArray getData() {
	return data;
    }

    public void setData(ModifiableByteArray data) {
	this.data = data;
    }

    public void setData(byte[] data) {
	if (this.data == null) {
	    this.data = new ModifiableByteArray();
	}
	this.data.setOriginalValue(data);
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
	ApplicationHandler ah = new ApplicationHandler(tlsContext);
	ah.setProtocolMessage(this);
	return ah;
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\nApplication Data:");
	return sb.toString();
    }

    @Override
    public String toCompactString() {
	return "Application";
    }
}
