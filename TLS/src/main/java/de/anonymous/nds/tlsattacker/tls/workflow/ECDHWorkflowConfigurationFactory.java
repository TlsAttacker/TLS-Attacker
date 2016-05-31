/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.tls.config.CommandConfig;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.application.ApplicationMessage;
import anonymous.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.FinishedMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import anonymous.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;

/**
 * Creates configuration of implemented ECDH(E) functionality in the protocol.
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ECDHWorkflowConfigurationFactory extends WorkflowConfigurationFactory {

    private final CommandConfig config;

    ECDHWorkflowConfigurationFactory(CommandConfig config) {
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

	if (config.getCipherSuites().get(0).isEphemeral()) {
	    workflowTrace.add(new ECDHEServerKeyExchangeMessage(ConnectionEnd.SERVER));
	}

	if (config.getKeystore() != null && config.isClientAuthentication()) {
	    workflowTrace.add(new CertificateRequestMessage(ConnectionEnd.SERVER));
	    workflowTrace.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));

	    workflowTrace.add(new CertificateMessage(ConnectionEnd.CLIENT));
	    workflowTrace.add(new ECDHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	    workflowTrace.add(new CertificateVerifyMessage(ConnectionEnd.CLIENT));
	} else {
	    workflowTrace.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));
	    workflowTrace.add(new ECDHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
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

}
