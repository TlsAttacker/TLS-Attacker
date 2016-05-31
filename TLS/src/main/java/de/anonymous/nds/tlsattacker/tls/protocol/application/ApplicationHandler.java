/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.application;

import anonymous.tlsattacker.tls.protocol.ProtocolMessageHandler;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import java.util.Arrays;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ApplicationHandler extends ProtocolMessageHandler<ApplicationMessage> {

    public ApplicationHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = ApplicationMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	protocolMessage.setData("test".getBytes());
	byte[] result = protocolMessage.getData().getValue();
	return result;
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	protocolMessage.setData(Arrays.copyOfRange(message, pointer, message.length));
	return pointer + message.length;
    }

}