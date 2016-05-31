/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls;

import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.config.ConfigHandlerFactory;
import anonymous.tlsattacker.tls.config.GeneralConfig;
import anonymous.tlsattacker.tls.constants.AlgorithmResolver;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.tls.constants.PublicKeyAlgorithm;
import anonymous.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateMessage;
import anonymous.tlsattacker.tls.protocol.handshake.FinishedMessage;
import anonymous.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.tls.workflow.WorkflowTraceType;
import anonymous.tlsattacker.tlsserver.KeyStoreGenerator;
import anonymous.tlsattacker.tlsserver.TLSServer;
import anonymous.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import java.util.Set;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class TlsClientTest {

    private static final Logger LOGGER = LogManager.getLogger(TlsClientTest.class);

    private TLSServer tlsServer;

    private static final int PORT = 56789;

    public TlsClientTest() {
	Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testRSAWorkflows() {
	try {
	    KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024);
	    KeyStore ks = KeyStoreGenerator.createKeyStore(k);
	    tlsServer = new TLSServer(ks, KeyStoreGenerator.PASSWORD, "TLS", PORT);
	    new Thread(tlsServer).start();
	    testExecuteWorkflows(PublicKeyAlgorithm.RSA, PORT);
	    tlsServer.shutdown();
	} catch (NoSuchAlgorithmException | CertificateException | IOException | InvalidKeyException
		| KeyStoreException | NoSuchProviderException | SignatureException | OperatorCreationException
		| UnrecoverableKeyException | KeyManagementException e) {
	    LOGGER.error("Unable to initialize the TLS server with an RSA key, but the build runs further.", e);
	}
    }

    @Test
    public void testECWorkflows() {
	try {
	    KeyPair k = KeyStoreGenerator.createECKeyPair(256);
	    KeyStore ks = KeyStoreGenerator.createKeyStore(k);
	    tlsServer = new TLSServer(ks, KeyStoreGenerator.PASSWORD, "TLS", PORT + 1);
	    new Thread(tlsServer).start();
	    testExecuteWorkflows(PublicKeyAlgorithm.EC, PORT + 1);
	    tlsServer.shutdown();
	} catch (NoSuchAlgorithmException | CertificateException | IOException | InvalidKeyException
		| KeyStoreException | NoSuchProviderException | SignatureException | OperatorCreationException
		| UnrecoverableKeyException | KeyManagementException e) {
	    LOGGER.error("Unable to initialize the TLS server with an EC key, but the build runs further.", e);
	}
    }

    /**
     * Test of executeWorkflow method, of class WorkflowExecutor.
     * 
     * @param algorithm
     * @param port
     */
    public void testExecuteWorkflows(PublicKeyAlgorithm algorithm, int port) {
	GeneralConfig generalConfig = new GeneralConfig();
	generalConfig.setLogLevel(Level.INFO);
	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initialize(generalConfig);

	ClientCommandConfig config = new ClientCommandConfig();
	config.setConnect("localhost:" + port);

	List<String> serverList = Arrays.asList(tlsServer.getCipherSuites());

	config.setProtocolVersion(ProtocolVersion.TLS10);
	testProtocolCompatibility(serverList, configHandler, config, algorithm);
	config.setProtocolVersion(ProtocolVersion.TLS11);
	testProtocolCompatibility(serverList, configHandler, config, algorithm);
	config.setProtocolVersion(ProtocolVersion.TLS12);
	testProtocolCompatibility(serverList, configHandler, config, algorithm);

	if (algorithm == PublicKeyAlgorithm.RSA) {
	    testCustomWorkflow(port);
	}
    }

    private void testProtocolCompatibility(List<String> serverList, ConfigHandler configHandler,
	    ClientCommandConfig config, PublicKeyAlgorithm algorithm) {
	LOGGER.info(config.getProtocolVersion());
	for (CipherSuite cs : CipherSuite.getImplemented()) {
	    Set<PublicKeyAlgorithm> requiredAlgorithms = AlgorithmResolver.getRequiredKeystoreAlgorithms(cs);
	    requiredAlgorithms.remove(algorithm);
	    if (serverList.contains(cs.toString()) && cs.isSupportedInProtocol(config.getProtocolVersion())
		    && requiredAlgorithms.isEmpty()) {
		LOGGER.info("Testing: {}", cs);
		LinkedList<CipherSuite> cslist = new LinkedList<>();
		cslist.add(cs);
		config.setCipherSuites(cslist);
		testExecuteWorkflow(configHandler, config);
	    }
	}
    }

    private void testExecuteWorkflow(ConfigHandler configHandler, ClientCommandConfig config) {

	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	workflowExecutor.executeWorkflow();

	transportHandler.closeConnection();

	assertTrue(tlsContext.getWorkflowTrace().containsServerFinished());
    }

    private void testCustomWorkflow(int port) {
	GeneralConfig generalConfig = new GeneralConfig();
	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initialize(generalConfig);

	ClientCommandConfig config = new ClientCommandConfig();
	config.setConnect("localhost:" + port);
	config.setWorkflowTraceType(WorkflowTraceType.CLIENT_HELLO);

	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();
	trace.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	trace.add(new CertificateMessage(ConnectionEnd.SERVER));
	trace.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));
	trace.add(new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	trace.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	trace.add(new FinishedMessage(ConnectionEnd.CLIENT));
	trace.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	trace.add(new FinishedMessage(ConnectionEnd.SERVER));

	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	workflowExecutor.executeWorkflow();

	transportHandler.closeConnection();

	assertTrue(tlsContext.getWorkflowTrace().containsServerFinished());
    }

}
