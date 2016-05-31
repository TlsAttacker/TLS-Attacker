/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.tls.constants.HandshakeByteLength;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class HelloRequestHandler extends HandshakeMessageHandler<HelloRequestMessage> {

    public HelloRequestHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = HelloRequestMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {

	protocolMessage.setLength(0);

	long header = (HandshakeMessageType.HELLO_REQUEST.getValue() << 24) + protocolMessage.getLength().getValue();

	protocolMessage.setCompleteResultingMessage(ArrayConverter.longToUint32Bytes(header));

	return protocolMessage.getCompleteResultingMessage().getValue();
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.HELLO_REQUEST.getValue()) {
	    throw new InvalidMessageTypeException("This is not a Hello Request message");
	}
	protocolMessage.setType(message[pointer]);

	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setLength(length);
	// should always be null

	currentPointer = nextPointer;

	protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, nextPointer));

	return currentPointer;
    }
}
