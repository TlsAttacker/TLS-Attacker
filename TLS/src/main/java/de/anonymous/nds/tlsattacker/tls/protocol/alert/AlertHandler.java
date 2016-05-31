/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.alert;

import anonymous.tlsattacker.tls.protocol.ProtocolMessageHandler;
import anonymous.tlsattacker.tls.workflow.TlsContext;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class AlertHandler extends ProtocolMessageHandler<AlertMessage> {

    public AlertHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = AlertMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	protocolMessage.setLevel(protocolMessage.getConfig()[0]);
	protocolMessage.setDescription(protocolMessage.getConfig()[1]);
	byte[] result = { protocolMessage.getLevel().getValue(), protocolMessage.getDescription().getValue() };
	protocolMessage.setCompleteResultingMessage(result);
	return result;
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	protocolMessage.setLevel(message[pointer]);
	protocolMessage.setDescription(message[pointer + 1]);
	return (pointer + 2);
    }
}
