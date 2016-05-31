/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.tls.config.CommandConfig;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.application.ApplicationMessage;
import anonymous.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import anonymous.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.FinishedMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import anonymous.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import java.util.List;

/**
 * Creates configuration of implemented RSA functionality in the protocol.
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class RsaWorkflowConfigurationFactory extends WorkflowConfigurationFactory {

    private final CommandConfig config;

    RsaWorkflowConfigurationFactory(CommandConfig config) {
	this.config = config;
    }

    @Override
    public TlsContext createClientHelloTlsContext() {
	TlsContext context = new TlsContext();
	context.setProtocolVersion(config.getProtocolVersion());
	context.setSelectedCipherSuite(config.getCipherSuites().get(0));
	WorkflowTrace workflowTrace = new WorkflowTrace();

	ClientHelloMessage ch = new ClientHelloMessage(ConnectionEnd.CLIENT);
	workflowTrace.add(ch);

	ch.setSupportedCipherSuites(config.getCipherSuites());
	ch.setSupportedCompressionMethods(config.getCompressionMethods());

	initializeClientHelloExtensions(config, ch);

	context.setWorkflowTrace(workflowTrace);
	initializeProtocolMessageOrder(context);

	return context;
    }

    @Override
    public TlsContext createHandshakeTlsContext() {
	TlsContext context = this.createClientHelloTlsContext();
	WorkflowTrace workflowTrace = context.getWorkflowTrace();

	workflowTrace.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	workflowTrace.add(new CertificateMessage(ConnectionEnd.SERVER));
	if (config.getKeystore() != null && config.isClientAuthentication()) {
	    workflowTrace.add(new CertificateRequestMessage(ConnectionEnd.SERVER));
	    workflowTrace.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));

	    workflowTrace.add(new CertificateMessage(ConnectionEnd.CLIENT));
	    workflowTrace.add(new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	    workflowTrace.add(new CertificateVerifyMessage(ConnectionEnd.CLIENT));
	} else {
	    workflowTrace.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));
	    workflowTrace.add(new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	}

	workflowTrace.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	workflowTrace.add(new FinishedMessage(ConnectionEnd.CLIENT));

	workflowTrace.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	workflowTrace.add(new FinishedMessage(ConnectionEnd.SERVER));

	initializeProtocolMessageOrder(context);

	return context;
    }

    @Override
    public TlsContext createFullTlsContext() {
	TlsContext context = this.createHandshakeTlsContext();
	WorkflowTrace workflowTrace = context.getWorkflowTrace();

	workflowTrace.add(new ApplicationMessage(ConnectionEnd.CLIENT));

	if (config.getHeartbeatMode() != null) {
	    workflowTrace.add(new HeartbeatMessage(ConnectionEnd.CLIENT));
	    workflowTrace.add(new HeartbeatMessage(ConnectionEnd.SERVER));
	}

	initializeProtocolMessageOrder(context);

	return context;
    }

    @Override
    public TlsContext createFullServerResponseTlsContext() {
	TlsContext context = this.createFullTlsContext();

	List<ProtocolMessage> protocolMessages = context.getWorkflowTrace().getProtocolMessages();

	protocolMessages.add(new ApplicationMessage(ConnectionEnd.SERVER));

	initializeProtocolMessageOrder(context);

	return context;
    }
}
