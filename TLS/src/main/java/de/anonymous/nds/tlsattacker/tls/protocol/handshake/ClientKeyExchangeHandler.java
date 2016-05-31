/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.tls.constants.AlgorithmResolver;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.constants.HandshakeByteLength;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import anonymous.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @param <HandshakeMessage>
 */
public abstract class ClientKeyExchangeHandler<HandshakeMessage extends ClientKeyExchangeMessage> extends
	HandshakeMessageHandler<HandshakeMessage> {

    KeyExchangeAlgorithm keyExchangeAlgorithm;

    public ClientKeyExchangeHandler(TlsContext tlsContext) {
	super(tlsContext);
    }

    @Override
    public byte[] prepareMessageAction() {
	protocolMessage.setType(HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue());
	CipherSuite selectedCipherSuite = tlsContext.getSelectedCipherSuite();
	KeyExchangeAlgorithm keyExchange = AlgorithmResolver.getKeyExchangeAlgorithm(selectedCipherSuite);
	if (keyExchange != keyExchangeAlgorithm) {
	    throw new UnsupportedOperationException("The selected key exchange algorithm (" + keyExchange
		    + ") is not supported yet");
	}
	byte[] result = this.prepareKeyExchangeMessage();
	protocolMessage.setLength(result.length);
	long header = (protocolMessage.getType().getValue() << 24) + protocolMessage.getLength().getValue();
	protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
		ArrayConverter.longToUint32Bytes(header), result));

	return protocolMessage.getCompleteResultingMessage().getValue();
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue()) {
	    throw new InvalidMessageTypeException("This is not a Client key exchange message");
	}
	protocolMessage.setType(message[pointer]);

	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setLength(length);
	currentPointer = nextPointer;

	int resultPointer = this.parseKeyExchangeMessage(message, currentPointer);

	currentPointer = resultPointer;

	protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, currentPointer));

	return currentPointer;
    }

    abstract byte[] prepareKeyExchangeMessage();

    abstract int parseKeyExchangeMessage(byte[] message, int pointer);
}
