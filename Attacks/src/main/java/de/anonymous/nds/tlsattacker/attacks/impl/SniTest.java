/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.impl;

import anonymous.tlsattacker.attacks.config.SniTestCommandConfig;
import anonymous.tlsattacker.tls.Attacker;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.constants.NameType;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.extension.ServerNameIndicationExtensionMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.transport.TransportHandler;
import anonymous.tlsattacker.util.UnoptimizedDeepCopy;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends different server names in the SNI extension in the ClientHello
 * messages.
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class SniTest extends Attacker<SniTestCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(SniTest.class);

    public SniTest(SniTestCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();
	List<ProtocolMessage> messages = trace.getProtocolMessages();
	ServerNameIndicationExtensionMessage sni = new ServerNameIndicationExtensionMessage();
	sni.setServerNameConfig(config.getServerName2());
	sni.setNameTypeConfig(NameType.HOST_NAME);
	ClientHelloMessage ch2 = (ClientHelloMessage) UnoptimizedDeepCopy.copy(messages.get(0));
	ch2.addExtension(sni);
	messages.add(ch2);
	messages.add(new ServerHelloMessage());
	messages.add(new CertificateMessage());

	workflowExecutor.executeWorkflow();
	transportHandler.closeConnection();

    }

}
