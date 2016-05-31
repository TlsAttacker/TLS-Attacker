/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.tls.constants.AlgorithmResolver;
import anonymous.tlsattacker.tls.crypto.PseudoRandomFunction;
import anonymous.tlsattacker.tls.exceptions.WorkflowExecutionException;
import anonymous.tlsattacker.tls.constants.HandshakeByteLength;
import anonymous.tlsattacker.tls.constants.PRFAlgorithm;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.tls.ServerDHParams;
import org.bouncycastle.crypto.tls.TlsDHUtils;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.BigIntegers;

/**
 * Handler for DH and DHE ClientKeyExchange messages
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class DHClientKeyExchangeHandler extends ClientKeyExchangeHandler<DHClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(DHClientKeyExchangeHandler.class);

    public DHClientKeyExchangeHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = DHClientKeyExchangeMessage.class;
	this.keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(tlsContext.getSelectedCipherSuite());
    }

    @Override
    public int parseKeyExchangeMessage(byte[] message, int currentPointer) {
	int nextPointer = currentPointer + HandshakeByteLength.DH_PARAM_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setSerializedPublicKeyLength(length);
	currentPointer = nextPointer;

	nextPointer = currentPointer + length;
	protocolMessage.setSerializedPublicKey(Arrays.copyOfRange(message, currentPointer, nextPointer));
	BigInteger publicKey = new BigInteger(1, Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setY(publicKey);

	byte[] premasterSecret;

	DHPublicKeyParameters clientPubParameters = new DHPublicKeyParameters(protocolMessage.getY().getValue(),
		tlsContext.getServerDHParameters().getPublicKey().getParameters());

	premasterSecret = TlsDHUtils.calculateDHBasicAgreement(clientPubParameters,
		tlsContext.getServerDHPrivateKeyParameters());

	LOGGER.debug("Resulting premaster secret: {}", ArrayConverter.bytesToHexString(premasterSecret));

	protocolMessage.setPremasterSecret(premasterSecret);

	byte[] random = tlsContext.getClientServerRandom();

	PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(tlsContext.getProtocolVersion(),
		tlsContext.getSelectedCipherSuite());
	byte[] masterSecret = PseudoRandomFunction.compute(prfAlgorithm, protocolMessage.getPremasterSecret()
		.getValue(), PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
	protocolMessage.setMasterSecret(masterSecret);
	LOGGER.debug("Computed Master Secret: {}", ArrayConverter.bytesToHexString(masterSecret));

	tlsContext.setMasterSecret(protocolMessage.getMasterSecret().getValue());

	currentPointer = nextPointer;

	return currentPointer;
    }

    @Override
    byte[] prepareKeyExchangeMessage() {
	if (tlsContext.getServerDHParameters() == null) {
	    // we are probably handling a simple DH ciphersuite, we try to
	    // establish server public key parameters from the server
	    // certificate message
	    Certificate x509Cert = tlsContext.getServerCertificate();

	    SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
	    DHPublicKeyParameters parameters;
	    try {
		parameters = (DHPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
		tlsContext.setServerDHParameters(new ServerDHParams(parameters));
	    } catch (IOException e) {
		throw new WorkflowExecutionException("Problem in parsing public key parameters from certificate", e);
	    }
	}

	byte[] premasterSecret;

	// generate client's original dh public and private key, based on
	// the
	// server's public parameters
	AsymmetricCipherKeyPair kp = TlsDHUtils.generateDHKeyPair(new SecureRandom(), tlsContext
		.getServerDHParameters().getPublicKey().getParameters());
	DHPublicKeyParameters dhPublic = (DHPublicKeyParameters) kp.getPublic();
	DHPrivateKeyParameters dhPrivate = (DHPrivateKeyParameters) kp.getPrivate();

	protocolMessage.setG(dhPublic.getParameters().getG());
	protocolMessage.setP(dhPublic.getParameters().getP());
	protocolMessage.setY(dhPublic.getY());
	protocolMessage.setX(dhPrivate.getX());

	// set the modified values of client's private and public parameters
	DHParameters newParams = new DHParameters(protocolMessage.getP().getValue(), protocolMessage.getG().getValue());
	// DHPublicKeyParameters newDhPublic = new
	// DHPublicKeyParameters(dhMessage.getY().getValue(), newParams);
	DHPrivateKeyParameters newDhPrivate = new DHPrivateKeyParameters(protocolMessage.getX().getValue(), newParams);

	premasterSecret = TlsDHUtils.calculateDHBasicAgreement(tlsContext.getServerDHParameters().getPublicKey(),
		newDhPrivate);

	protocolMessage.setPremasterSecret(premasterSecret);
	LOGGER.debug("Computed PreMaster Secret: {}",
		ArrayConverter.bytesToHexString(protocolMessage.getPremasterSecret().getValue()));

	byte[] serializedPublicKey = BigIntegers.asUnsignedByteArray(protocolMessage.getY().getValue());
	protocolMessage.setSerializedPublicKey(serializedPublicKey);
	protocolMessage.setSerializedPublicKeyLength(serializedPublicKey.length);

	byte[] result = ArrayConverter.concatenate(ArrayConverter.intToBytes(protocolMessage
		.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.DH_PARAM_LENGTH), protocolMessage
		.getSerializedPublicKey().getValue());

	byte[] random = tlsContext.getClientServerRandom();

	PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(tlsContext.getProtocolVersion(),
		tlsContext.getSelectedCipherSuite());
	byte[] masterSecret = PseudoRandomFunction.compute(prfAlgorithm, protocolMessage.getPremasterSecret()
		.getValue(), PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
	LOGGER.debug("Computed Master Secret: {}", ArrayConverter.bytesToHexString(masterSecret));

	protocolMessage.setMasterSecret(masterSecret);
	tlsContext.setMasterSecret(protocolMessage.getMasterSecret().getValue());

	return result;

    }
}
