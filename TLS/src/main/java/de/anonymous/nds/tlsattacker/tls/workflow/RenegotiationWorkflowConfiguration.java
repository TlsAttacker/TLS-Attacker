/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.constants.CompressionMethod;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.application.ApplicationMessage;
import anonymous.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import anonymous.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.FinishedMessage;
import anonymous.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import static anonymous.tlsattacker.tls.workflow.WorkflowConfigurationFactory.initializeProtocolMessageOrder;
import java.util.LinkedList;
import java.util.List;

/**
 * Creates Workflowtrace for Renegotiation with Client Authentication
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class RenegotiationWorkflowConfiguration {

    private final TlsContext tlsContext;

    public RenegotiationWorkflowConfiguration(TlsContext tlsContext) {
	this.tlsContext = tlsContext;
    }

    public void createWorkflow() {
	ProtocolMessage lastMessage = tlsContext.getWorkflowTrace().getLastProtocolMesssage();
	WorkflowTrace workflowTrace;
	if (lastMessage.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
	    workflowTrace = createHandshakeWorkflow();
	} else if (lastMessage.getProtocolMessageType() == ProtocolMessageType.APPLICATION_DATA
		&& lastMessage.getMessageIssuer() == ConnectionEnd.CLIENT) {
	    workflowTrace = createFullWorkflow();
	} else {
	    workflowTrace = createFullSRWorkflow();
	}

	tlsContext.setWorkflowTrace(workflowTrace);

	initializeProtocolMessageOrder(tlsContext);

	tlsContext.setRenegotiation(true);
    }

    private WorkflowTrace createHandshakeWorkflow() {

	WorkflowTrace workflowTrace = new WorkflowTrace();

	List<ProtocolMessage> protocolMessages = new LinkedList<>();

	ClientHelloMessage ch = new ClientHelloMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(ch);

	List<CipherSuite> ciphers = new LinkedList<>();
	ciphers.add(tlsContext.getSelectedCipherSuite());
	ch.setSupportedCipherSuites(ciphers);
	List<CompressionMethod> compressions = new LinkedList<>();
	compressions.add(CompressionMethod.NULL);
	ch.setSupportedCompressionMethods(compressions);

	protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new CertificateMessage(ConnectionEnd.SERVER));

	if (tlsContext.getSelectedCipherSuite().isEphemeral()) {
	    if (tlsContext.getSelectedCipherSuite().name().contains("_DHE_")) {
		protocolMessages.add(new DHEServerKeyExchangeMessage(ConnectionEnd.SERVER));
	    } else {
		protocolMessages.add(new ECDHEServerKeyExchangeMessage(ConnectionEnd.SERVER));
	    }
	}

	if (tlsContext.isClientAuthentication()) {
	    protocolMessages.add(new CertificateRequestMessage(ConnectionEnd.SERVER));
	}

	protocolMessages.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));

	if (tlsContext.isClientAuthentication()) {
	    protocolMessages.add(new CertificateMessage(ConnectionEnd.CLIENT));
	}

	if (tlsContext.getSelectedCipherSuite().name().contains("_DH")) {
	    protocolMessages.add(new DHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	} else if (tlsContext.getSelectedCipherSuite().name().contains("_ECDH")) {
	    protocolMessages.add(new ECDHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	} else {
	    protocolMessages.add(new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	}

	if (tlsContext.isClientAuthentication()) {
	    protocolMessages.add(new CertificateVerifyMessage(ConnectionEnd.CLIENT));
	}

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.CLIENT));

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.SERVER));

	workflowTrace.setProtocolMessages(protocolMessages);

	return workflowTrace;

    }

    private WorkflowTrace createFullWorkflow() {

	WorkflowTrace workflowTrace = this.createHandshakeWorkflow();

	List<ProtocolMessage> protocolMessages = workflowTrace.getProtocolMessages();

	protocolMessages.add(new ApplicationMessage(ConnectionEnd.CLIENT));

	workflowTrace.setProtocolMessages(protocolMessages);

	return workflowTrace;
    }

    private WorkflowTrace createFullSRWorkflow() {

	WorkflowTrace workflowTrace = this.createFullWorkflow();

	List<ProtocolMessage> protocolMessages = workflowTrace.getProtocolMessages();

	protocolMessages.add(new ApplicationMessage(ConnectionEnd.SERVER));

	workflowTrace.setProtocolMessages(protocolMessages);

	return workflowTrace;
    }

}
