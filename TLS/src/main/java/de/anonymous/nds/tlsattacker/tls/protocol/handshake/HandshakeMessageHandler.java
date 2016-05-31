/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.tls.protocol.ProtocolMessageHandler;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.ArrayConverter;

/**
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 * @author anonymous Pfützenreuter <anonymous.pfuetzenreuter@anonymous>
 * @param <ProtocolMessage>
 */
public abstract class HandshakeMessageHandler<ProtocolMessage extends HandshakeMessage> extends
	ProtocolMessageHandler<ProtocolMessage> {

    private byte[] dtlsAllMessageBytes;

    public HandshakeMessageHandler(TlsContext tlsContext) {
	super(tlsContext);
    }

    @Override
    protected byte[] beforeParseMessageAction(byte[] message, int pointer) {
	if (tlsContext.getProtocolVersion() == ProtocolVersion.DTLS12) {
	    return prepareDtlsHandshakeMessageParse(message, pointer);
	}
	return message;
    }

    /**
     * Implementation hook used after the prepareMessageAction: the content of
     * the parsed protocol message is parsed and the digest value is updated
     * 
     * @param messageBytes
     * @return
     */
    @Override
    protected byte[] afterPrepareMessageAction(byte[] messageBytes) {
	if (tlsContext.getProtocolVersion() == ProtocolVersion.DTLS12) {
	    protocolMessage.setCompleteResultingMessage(finishDtlsHandshakeMessagePrepare(messageBytes));
	}
	byte[] pm = protocolMessage.getCompleteResultingMessage().getValue();
	if (protocolMessage.getIncludeInDigest()) {
	    tlsContext.getDigest().update(pm);
	}
	return pm;
    }

    /**
     * Implementation hook used after the parseMessageAction: the content of the
     * parsed protocol message is parsed and the digest value is updated
     * 
     * @param ret
     * @return
     */
    @Override
    protected int afterParseMessageAction(int ret) {
	if (tlsContext.getProtocolVersion() == ProtocolVersion.DTLS12) {
	    protocolMessage.setCompleteResultingMessage(dtlsAllMessageBytes);
	    ret += 8;
	}
	byte[] pm = protocolMessage.getCompleteResultingMessage().getValue();
	if (protocolMessage.getIncludeInDigest()) {
	    tlsContext.getDigest().update(pm);
	}
	return ret;
    }

    private byte[] prepareDtlsHandshakeMessageParse(byte[] message, int pointer) {
	dtlsAllMessageBytes = message;
	byte[] parsePmBytes;

	protocolMessage.setMessageSeq((message[pointer + 4] << 8) + (message[pointer + 5] & 0xFF));
	protocolMessage.setFragmentOffset((message[pointer + 6] << 16) + (message[pointer + 7] << 8)
		+ (message[pointer + 8] & 0xFF));
	protocolMessage.setFragmentLength((message[pointer + 9] << 16) + (message[pointer + 10] << 8)
		+ (message[pointer + 11] & 0xFF));

	parsePmBytes = new byte[message.length - 8];
	System.arraycopy(message, 0, parsePmBytes, 0, pointer);
	System.arraycopy(message, pointer, parsePmBytes, pointer, 4);
	System.arraycopy(message, pointer + 12, parsePmBytes, pointer + 4, message.length - pointer - 12);

	return parsePmBytes;
    }

    private byte[] finishDtlsHandshakeMessagePrepare(byte[] messageBytes) {
	protocolMessage.setFragmentLength(messageBytes.length - 4);
	byte[] preparePmBytes = new byte[messageBytes.length + 8];

	System.arraycopy(messageBytes, 0, preparePmBytes, 0, 4);
	System.arraycopy(ArrayConverter.intToBytes(protocolMessage.getMessageSeq().getValue(), 2), 0, preparePmBytes,
		4, 2);
	System.arraycopy(ArrayConverter.intToBytes(protocolMessage.getFragmentOffset().getValue(), 3), 0,
		preparePmBytes, 6, 3);
	System.arraycopy(ArrayConverter.intToBytes(protocolMessage.getFragmentLength().getValue(), 3), 0,
		preparePmBytes, 9, 3);
	System.arraycopy(messageBytes, 4, preparePmBytes, 12, messageBytes.length - 4);

	return preparePmBytes;
    }

}
