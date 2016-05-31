/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config;

import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.exceptions.ConfigurationException;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import anonymous.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.transport.TransportHandler;
import anonymous.tlsattacker.transport.TransportHandlerFactory;
import anonymous.tlsattacker.util.KeystoreHandler;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ServerConfigHandler extends ConfigHandler {

    @Override
    public TransportHandler initializeTransportHandler(CommandConfig config) throws ConfigurationException {
	ServerCommandConfig ccConfig = (ServerCommandConfig) config;
	TransportHandler th = TransportHandlerFactory.createTransportHandler(config.getTransportHandlerType(),
		config.getTlsTimeout());
	try {
	    String host = "server";
	    int port = Integer.parseInt(ccConfig.getPort());
	    th.initialize(host, port);
	    return th;
	} catch (ArrayIndexOutOfBoundsException | NullPointerException | NumberFormatException ex) {
	    throw new ConfigurationException(ccConfig.getPort() + " is an invalid string for host:port configuration",
		    ex);
	} catch (IOException ex) {
	    throw new ConfigurationException("Unable to initialize the transport handler with: " + ccConfig.getPort(),
		    ex);
	}
    }

    @Override
    public TlsContext initializeTlsContext(CommandConfig config) {
	ServerCommandConfig ccConfig = (ServerCommandConfig) config;
	TlsContext tlsContext;
	if (ccConfig.getWorkflowInput() != null) {
	    try {
		tlsContext = new TlsContext();
		FileInputStream fis = new FileInputStream(ccConfig.getWorkflowInput());
		WorkflowTrace workflowTrace = WorkflowTraceSerializer.read(fis);
		tlsContext.setWorkflowTrace(workflowTrace);
		if (workflowTrace.getProtocolVersion() != null) {
		    tlsContext.setProtocolVersion(workflowTrace.getProtocolVersion());
		}
	    } catch (IOException | JAXBException | XMLStreamException ex) {
		throw new ConfigurationException("The workflow trace could not be loaded from "
			+ ccConfig.getWorkflowInput(), ex);
	    }
	} else {
	    WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(config);
	    switch (ccConfig.getWorkflowTraceType()) {
		case FULL_SERVER_RESPONSE:
		    tlsContext = factory.createFullServerResponseTlsContext();
		    break;
		case FULL:
		    tlsContext = factory.createFullTlsContext();
		    break;
		case HANDSHAKE:
		    tlsContext = factory.createHandshakeTlsContext();
		    break;
		case CLIENT_HELLO:
		    tlsContext = factory.createClientHelloTlsContext();
		    break;
		default:
		    throw new ConfigurationException("not supported workflow type: " + ccConfig.getWorkflowTraceType());
	    }

	}
	tlsContext.setMyConnectionEnd(ConnectionEnd.SERVER);

	if (config.isClientAuthentication()) {
	    tlsContext.setClientAuthentication(true);
	}
	if (config.getKeystore() != null) {
	    try {
		KeyStore ks = KeystoreHandler.loadKeyStore(config.getKeystore(), config.getPassword());
		tlsContext.setKeyStore(ks);
		tlsContext.setAlias(config.getAlias());
		tlsContext.setPassword(config.getPassword());
		if (LOGGER.isDebugEnabled()) {
		    Enumeration<String> aliases = ks.aliases();
		    LOGGER.debug("Successfully read keystore with the following aliases: ");
		    while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			LOGGER.debug("  {}", alias);
		    }
		}
	    } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
		LOGGER.error(ex);
		throw new ConfigurationException(ex.getLocalizedMessage(), ex);
	    }
	}

	return tlsContext;
    }

    @Override
    public WorkflowExecutor initializeWorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext) {
	WorkflowExecutor executor = WorkflowExecutorFactory.createWorkflowExecutor(transportHandler, tlsContext);
	return executor;
    }

}
