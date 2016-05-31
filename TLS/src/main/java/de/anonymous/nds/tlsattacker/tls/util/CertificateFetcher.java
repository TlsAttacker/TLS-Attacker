/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.util;

import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.config.ClientConfigHandler;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import anonymous.tlsattacker.transport.TransportHandler;
import java.security.PublicKey;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class CertificateFetcher {

    private CertificateFetcher() {

    }

    public static PublicKey fetchServerPublicKey(String connect, List<CipherSuite> cipherSuites) {
	ClientCommandConfig config = new ClientCommandConfig();
	config.setConnect(connect);
	config.setCipherSuites(cipherSuites);
	X509CertificateObject cert = fetchServerCertificate(config);
	return cert.getPublicKey();
    }

    public static X509CertificateObject fetchServerCertificate(String connect, List<CipherSuite> cipherSuites) {
	ClientCommandConfig config = new ClientCommandConfig();
	config.setConnect(connect);
	config.setCipherSuites(cipherSuites);
	return fetchServerCertificate(config);
    }

    public static PublicKey fetchServerPublicKey(ClientCommandConfig config) {
	X509CertificateObject cert = fetchServerCertificate(config);
	return cert.getPublicKey();
    }

    public static X509CertificateObject fetchServerCertificate(ClientCommandConfig config) {
	ConfigHandler configHandler = new ClientConfigHandler();
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext context = configHandler.initializeTlsContext(config);

	context.setProtocolVersion(config.getProtocolVersion());
	context.setSelectedCipherSuite(config.getCipherSuites().get(0));
	WorkflowTrace workflowTrace = new WorkflowTrace();

	List<ProtocolMessage> protocolMessages = new LinkedList<>();
	ClientHelloMessage ch = new ClientHelloMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(ch);
	protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new CertificateMessage(ConnectionEnd.SERVER));

	ch.setSupportedCipherSuites(config.getCipherSuites());
	ch.setSupportedCompressionMethods(config.getCompressionMethods());

	WorkflowConfigurationFactory.initializeClientHelloExtensions(config, ch);
	workflowTrace.setProtocolMessages(protocolMessages);

	context.setWorkflowTrace(workflowTrace);

	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, context);

	workflowExecutor.executeWorkflow();

	transportHandler.closeConnection();

	return context.getX509ServerCertificateObject();
    }
}
