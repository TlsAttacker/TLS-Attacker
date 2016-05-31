/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.mitm;

import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.config.CommandConfig;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.exceptions.ConfigurationException;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.application.ApplicationMessage;
import anonymous.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import anonymous.tlsattacker.tls.protocol.handshake.FinishedMessage;
import anonymous.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import static anonymous.tlsattacker.tls.workflow.WorkflowConfigurationFactory.initializeProtocolMessageOrder;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.tls.workflow.WorkflowTraceType;
import java.util.LinkedList;
import java.util.List;

/**
 * Creates an RSA example-workflowtrace to for Man-in-the-Middle Attack This
 * workflow automatically synchronizes the master secret
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class RSAExampleMitMWorkflowConfiguration {

    private final TlsContext tlsContext;
    private final CommandConfig config;

    public RSAExampleMitMWorkflowConfiguration(TlsContext tlsContext, CommandConfig config) {
	this.tlsContext = tlsContext;
	this.config = config;
    }

    public void createWorkflow() {

	ClientCommandConfig ccConfig = (ClientCommandConfig) config;
	WorkflowTraceType workflowTraceType = ccConfig.getWorkflowTraceType();

	WorkflowTrace workflowTrace;

	switch (workflowTraceType) {
	    case FULL_SERVER_RESPONSE:
		workflowTrace = createFullSRWorkflow();
		break;
	    case FULL:
		workflowTrace = createFullWorkflow();
		break;
	    case HANDSHAKE:
		workflowTrace = createHandshakeWorkflow();
		break;
	    default:
		throw new ConfigurationException("not supported workflow type: " + workflowTraceType);
	}

	tlsContext.setWorkflowTrace(workflowTrace);

	initializeProtocolMessageOrder(tlsContext);
    }

    private WorkflowTrace createHandshakeWorkflow() {

	WorkflowTrace workflowTrace = new WorkflowTrace();

	List<ProtocolMessage> protocolMessages = new LinkedList<>();

	ClientHelloMessage ch = new ClientHelloMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(ch);
	ch.setGoingToBeSent(false);

	ch.setSupportedCipherSuites(config.getCipherSuites());
	ch.setSupportedCompressionMethods(config.getCompressionMethods());

	ServerHelloMessage sh = new ServerHelloMessage(ConnectionEnd.SERVER);
	protocolMessages.add(sh);
	CertificateMessage cm = new CertificateMessage(ConnectionEnd.SERVER);
	protocolMessages.add(cm);
	cm.setGoingToBeSent(false);

	if (tlsContext.isClientAuthentication()) {
	    protocolMessages.add(new CertificateRequestMessage(ConnectionEnd.SERVER));
	}

	protocolMessages.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));

	if (tlsContext.isClientAuthentication()) {
	    protocolMessages.add(new CertificateMessage(ConnectionEnd.CLIENT));
	}

	RSAClientKeyExchangeMessage kem = new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(kem);
	kem.setGoingToBeSent(false);

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

	ApplicationMessage cam = new ApplicationMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(cam);
	cam.setGoingToBeSent(false);

	workflowTrace.setProtocolMessages(protocolMessages);

	return workflowTrace;
    }

    private WorkflowTrace createFullSRWorkflow() {

	WorkflowTrace workflowTrace = this.createFullWorkflow();

	List<ProtocolMessage> protocolMessages = workflowTrace.getProtocolMessages();

	ApplicationMessage sam = new ApplicationMessage(ConnectionEnd.SERVER);
	protocolMessages.add(sam);
	sam.setGoingToBeModified(true);

	workflowTrace.setProtocolMessages(protocolMessages);

	return workflowTrace;
    }

}
