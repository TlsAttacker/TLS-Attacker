/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.tls.crypto.ECCUtilsBCWrapper;
import anonymous.tlsattacker.tls.constants.HandshakeByteLength;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import anonymous.tlsattacker.tls.exceptions.WorkflowExecutionException;
import anonymous.tlsattacker.tls.constants.EllipticCurveType;
import anonymous.tlsattacker.tls.constants.HashAlgorithm;
import anonymous.tlsattacker.tls.constants.NamedCurve;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.tls.constants.SignatureAlgorithm;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ECDHEServerKeyExchangeHandler extends HandshakeMessageHandler<ECDHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(ECDHEServerKeyExchangeHandler.class);

    public ECDHEServerKeyExchangeHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = ECDHEServerKeyExchangeMessage.class;
    }

    /**
     * @param message
     * @param pointer
     * @return
     */
    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.SERVER_KEY_EXCHANGE.getValue()) {
	    throw new InvalidMessageTypeException(HandshakeMessageType.SERVER_KEY_EXCHANGE);
	}
	protocolMessage.setType(message[pointer]);

	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setLength(length);

	currentPointer = nextPointer;
	nextPointer++;
	EllipticCurveType ct = EllipticCurveType.getCurveType(message[currentPointer]);
	if (ct != EllipticCurveType.NAMED_CURVE) {
	    throw new UnsupportedOperationException("Currently only named curves are supported");
	}
	protocolMessage.setCurveType(ct.getValue());

	currentPointer = nextPointer;
	nextPointer = currentPointer + NamedCurve.LENGTH;
	NamedCurve nc = NamedCurve.getNamedCurve(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setNamedCurve(nc.getValue());

	currentPointer = nextPointer;
	nextPointer++;
	int publicKeyLength = message[currentPointer] & 0xFF;
	protocolMessage.setPublicKeyLength(publicKeyLength);

	currentPointer = nextPointer;
	nextPointer = currentPointer + publicKeyLength;
	protocolMessage.setPublicKey(Arrays.copyOfRange(message, currentPointer, nextPointer));

	byte[] ecParams = ArrayConverter.concatenate(new byte[] { protocolMessage.getCurveType().getValue() },
		protocolMessage.getNamedCurve().getValue(), ArrayConverter.intToBytes(protocolMessage
			.getPublicKeyLength().getValue(), 1), protocolMessage.getPublicKey().getValue());
	InputStream is = new ByteArrayInputStream(ecParams);

	try {
	    ECPublicKeyParameters publicKeyParameters = ECCUtilsBCWrapper.readECParametersWithPublicKey(is);
	    LOGGER.debug("Parsed the following EC domain parameters: ");
	    LOGGER.debug("  Curve order: {}", publicKeyParameters.getParameters().getCurve().getOrder());
	    LOGGER.debug("  Parameter A: {}", publicKeyParameters.getParameters().getCurve().getA());
	    LOGGER.debug("  Parameter B: {}", publicKeyParameters.getParameters().getCurve().getB());
	    LOGGER.debug("  Base point: {} ", publicKeyParameters.getParameters().getG());
	    LOGGER.debug("  Public key point Q: {} ", publicKeyParameters.getQ());

	    tlsContext.getEcContext().setServerPublicKeyParameters(publicKeyParameters);

	    if (tlsContext.getProtocolVersion() == ProtocolVersion.DTLS12
		    || tlsContext.getProtocolVersion() == ProtocolVersion.TLS12) {
		currentPointer = nextPointer;
		nextPointer++;
		HashAlgorithm ha = HashAlgorithm.getHashAlgorithm(message[currentPointer]);
		protocolMessage.setHashAlgorithm(ha.getValue());

		currentPointer = nextPointer;
		nextPointer++;
		SignatureAlgorithm sa = SignatureAlgorithm.getSignatureAlgorithm(message[currentPointer]);
		protocolMessage.setSignatureAlgorithm(sa.getValue());
	    }

	    currentPointer = nextPointer;
	    nextPointer = currentPointer + HandshakeByteLength.SIGNATURE_LENGTH;
	    int signatureLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	    protocolMessage.setSignatureLength(signatureLength);

	    currentPointer = nextPointer;
	    nextPointer = currentPointer + signatureLength;
	    protocolMessage.setSignature(Arrays.copyOfRange(message, currentPointer, nextPointer));

	    protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, nextPointer));

	    return nextPointer;
	} catch (IOException ex) {
	    ex.printStackTrace();
	    throw new WorkflowExecutionException("EC public key parsing failed", ex);
	}
    }

    @Override
    public byte[] prepareMessageAction() {
	throw new UnsupportedOperationException("Not supported yet.");
    }
}
