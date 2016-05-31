/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.heartbeat;

import anonymous.tlsattacker.tls.protocol.ProtocolMessageHandler;
import anonymous.tlsattacker.tls.constants.HandshakeByteLength;
import anonymous.tlsattacker.tls.constants.HeartbeatByteLength;
import anonymous.tlsattacker.tls.constants.HeartbeatMessageType;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.ArrayConverter;
import anonymous.tlsattacker.util.RandomHelper;
import java.util.Arrays;

/**
 * Handler for Heartbeat messages: http://tools.ietf.org/html/rfc6520#page-4
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class HeartbeatHandler extends ProtocolMessageHandler<HeartbeatMessage> {

    /**
     * max payload length used in our application (not set by the spec)
     */
    static final int MAX_PAYLOAD_LENGTH = 256;

    /**
     * according to the specification, the min padding length is 16
     */
    static final int MIN_PADDING_LENGTH = 16;

    /**
     * max padding length used in our application (not set by the spec)
     */
    static final int MAX_PADDING_LENGTH = 256;

    public HeartbeatHandler(TlsContext tlsContext) {
	super(tlsContext);
	correctProtocolMessageClass = HeartbeatMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	protocolMessage.setHeartbeatMessageType(HeartbeatMessageType.HEARTBEAT_REQUEST.getValue());

	int payloadLength = RandomHelper.getRandom().nextInt(MAX_PAYLOAD_LENGTH);

	byte[] payload = new byte[payloadLength];
	RandomHelper.getRandom().nextBytes(payload);
	protocolMessage.setPayload(payload);

	protocolMessage.setPayloadLength(protocolMessage.getPayload().getValue().length);

	// we create only 16 bytes of 0x00 padding (for convenience)
	// int paddingLength = randomGenerator.nextInt(MAX_PADDING_LENGTH) +
	// MIN_PADDING_LENGTH;
	int paddingLength = MIN_PADDING_LENGTH;
	byte[] padding = new byte[paddingLength];
	// randomGenerator.nextBytes(padding);
	protocolMessage.setPadding(padding);

	byte[] type = { protocolMessage.getHeartbeatMessageType().getValue() };
	byte[] result = ArrayConverter.concatenate(type, ArrayConverter.intToBytes(protocolMessage.getPayloadLength()
		.getValue(), HeartbeatByteLength.PAYLOAD_LENGTH), protocolMessage.getPayload().getValue(),
		protocolMessage.getPadding().getValue());

	protocolMessage.setCompleteResultingMessage(result);

	return result;
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	protocolMessage.setHeartbeatMessageType(message[pointer]);
	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
	int nextPointer = currentPointer + HeartbeatByteLength.PAYLOAD_LENGTH;
	int payloadLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setPayloadLength(payloadLength);

	currentPointer = nextPointer;
	nextPointer = nextPointer + payloadLength;
	protocolMessage.setPayload(Arrays.copyOfRange(message, currentPointer, nextPointer));

	currentPointer = nextPointer;
	nextPointer = message.length;
	protocolMessage.setPadding(Arrays.copyOfRange(message, currentPointer, nextPointer));

	return nextPointer;
    }

}
