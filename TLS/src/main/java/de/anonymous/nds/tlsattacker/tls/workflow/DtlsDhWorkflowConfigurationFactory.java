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
import anonymous.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage;
import anonymous.tlsattacker.dtls.protocol.handshake.HelloVerifyRequestMessage;
import anonymous.tlsattacker.tls.constants.AlertDescription;
import anonymous.tlsattacker.tls.constants.AlertLevel;
import anonymous.tlsattacker.tls.protocol.alert.AlertMessage;
import anonymous.tlsattacker.tls.protocol.handshake.FinishedMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import anonymous.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import anonymous.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;

/**
 * Creates configuration of implemented DH(E) functionality in the protocol.
 * 
 * @author anonymous Pfützenreuter <anonymous.pfuetzenreuter@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class DtlsDhWorkflowConfigurationFactory extends WorkflowConfigurationFactory {

    private final CommandConfig config;

    DtlsDhWorkflowConfigurationFactory(CommandConfig config) {
	this.config = config;
    }

    @Override
    public TlsContext createClientHelloTlsContext() {
	TlsContext context = new TlsContext();
	context.setProtocolVersion(config.getProtocolVersion());

	context.setSelectedCipherSuite(config.getCipherSuites().get(0));
	WorkflowTrace workflowTrace = new WorkflowTrace();

	ClientHelloDtlsMessage ch = new ClientHelloDtlsMessage(ConnectionEnd.CLIENT);
	workflowTrace.add(ch);

	ch.setSupportedCipherSuites(config.getCipherSuites());
	ch.setSupportedCompressionMethods(config.getCompressionMethods());
	ch.setIncludeInDigest(false);

	initializeClientHelloExtensions(config, ch);

	HelloVerifyRequestMessage hvrm = new HelloVerifyRequestMessage(ConnectionEnd.SERVER);
	hvrm.setIncludeInDigest(false);
	workflowTrace.add(hvrm);

	ch = new ClientHelloDtlsMessage(ConnectionEnd.CLIENT);
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
	    workflowTrace.add(new DHEServerKeyExchangeMessage(ConnectionEnd.SERVER));
	}
	if (config.getKeystore() != null && config.isClientAuthentication()) {
	    workflowTrace.add(new CertificateRequestMessage(ConnectionEnd.SERVER));
	    workflowTrace.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));
	    workflowTrace.add(new CertificateMessage(ConnectionEnd.CLIENT));
	    workflowTrace.add(new DHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	    workflowTrace.add(new CertificateVerifyMessage(ConnectionEnd.CLIENT));
	} else {
	    workflowTrace.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));
	    workflowTrace.add(new DHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
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

	AlertMessage alertMessage = new AlertMessage(ConnectionEnd.CLIENT);
	alertMessage.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
	workflowTrace.add(alertMessage);

	initializeProtocolMessageOrder(context);

	return context;
    }
}
