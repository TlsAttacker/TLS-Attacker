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
import anonymous.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import anonymous.tlsattacker.tls.constants.ClientCertificateType;
import anonymous.tlsattacker.tls.constants.SignatureAlgorithm;
import anonymous.tlsattacker.tls.constants.HashAlgorithm;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.LinkedList;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */

/**
 * @param <HandshakeMessage>
 */
public class CertificateRequestHandler<HandshakeMessage extends CertificateRequestMessage> extends
	HandshakeMessageHandler<HandshakeMessage> {

    public CertificateRequestHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = CertificateRequestMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	// TODO parse Arguments from Console and set properties with
	// Confighandler to support more Certificate types

	byte[] clientCertificateTypes = { ClientCertificateType.RSA_SIGN.getValue() };
	protocolMessage.setClientCertificateTypes(clientCertificateTypes);

	int clientCertificateTypesCount = protocolMessage.getClientCertificateTypes().getValue().length;
	protocolMessage.setClientCertificateTypesCount(clientCertificateTypesCount);

	byte[] signatureAndHashAlgorithms = new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA512)
		.getByteValue();
	signatureAndHashAlgorithms = ArrayConverter.concatenate(signatureAndHashAlgorithms,
		new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA384).getByteValue(),
		new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA256).getByteValue(),
		new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA224).getByteValue(),
		new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA1).getByteValue(),
		new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.MD5).getByteValue());
	protocolMessage.setSignatureHashAlgorithms(signatureAndHashAlgorithms);

	int signatureAndHashAlgorithmsCount = protocolMessage.getSignatureHashAlgorithms().getValue().length;
	protocolMessage.setSignatureHashAlgorithmsLength(signatureAndHashAlgorithmsCount);

	int distinguishedNamesLength = 0;
	protocolMessage.setDistinguishedNamesLength(distinguishedNamesLength);

	byte[] result = ArrayConverter.concatenate(ArrayConverter.intToBytes(protocolMessage
		.getClientCertificateTypesCount().getValue(), 1), protocolMessage.getClientCertificateTypes()
		.getValue(), ArrayConverter.intToBytes(protocolMessage.getSignatureHashAlgorithmsLength().getValue(),
		HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH), protocolMessage.getSignatureHashAlgorithms()
		.getValue(), ArrayConverter.intToBytes(protocolMessage.getDistinguishedNamesLength().getValue(),
		HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH));

	protocolMessage.setLength(result.length);

	long header = (HandshakeMessageType.CERTIFICATE_REQUEST.getValue() << 24)
		+ protocolMessage.getLength().getValue();

	protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
		ArrayConverter.longToUint32Bytes(header), result));

	return protocolMessage.getCompleteResultingMessage().getValue();

    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.CERTIFICATE_REQUEST.getValue()) {
	    throw new InvalidMessageTypeException("This is not a Certificate Request message");
	}
	protocolMessage.setType(message[pointer]);
	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;

	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setLength(length);
	currentPointer = nextPointer;

	nextPointer = currentPointer + 1;
	int certificateTypesCount = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setClientCertificateTypesCount(certificateTypesCount);
	currentPointer = nextPointer;

	nextPointer = currentPointer + certificateTypesCount;
	protocolMessage.setClientCertificateTypes(Arrays.copyOfRange(message, currentPointer, nextPointer));
	currentPointer = nextPointer;

	nextPointer = currentPointer + HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH;
	int signatureHashAlgorithmsLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer,
		nextPointer));
	protocolMessage.setSignatureHashAlgorithmsLength(signatureHashAlgorithmsLength);
	currentPointer = nextPointer;

	nextPointer = currentPointer + signatureHashAlgorithmsLength;
	protocolMessage.setSignatureHashAlgorithms(Arrays.copyOfRange(message, currentPointer, nextPointer));
	currentPointer = nextPointer;

	LinkedList<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = new LinkedList<>();
	for (int i = 0; i < protocolMessage.getSignatureHashAlgorithmsLength().getValue() / 2; i++) {
	    SignatureAndHashAlgorithm sha = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(Arrays.copyOfRange(
		    protocolMessage.getSignatureHashAlgorithms().getValue(), i * 2, i * 2 + 2));
	    signatureAndHashAlgorithms.add(sha);
	}
	tlsContext.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);

	nextPointer = currentPointer + HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH;
	int distinguishedNamesLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer,
		nextPointer));
	protocolMessage.setDistinguishedNamesLength(distinguishedNamesLength);
	currentPointer = nextPointer;

	nextPointer = currentPointer + distinguishedNamesLength;
	protocolMessage.setDistinguishedNames(Arrays.copyOfRange(message, currentPointer, nextPointer));
	currentPointer = nextPointer;

	protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, nextPointer));

	return currentPointer;
    }
}
