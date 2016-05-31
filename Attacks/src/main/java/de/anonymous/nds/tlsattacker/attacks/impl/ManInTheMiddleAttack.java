/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.impl;

import anonymous.tlsattacker.attacks.config.ManInTheMiddleAttackCommandConfig;
import anonymous.tlsattacker.attacks.mitm.MitMWorkflowExecutor;
import anonymous.tlsattacker.attacks.mitm.RSAExampleMitMWorkflowConfiguration;
import anonymous.tlsattacker.tls.Attacker;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.config.ConfigHandlerFactory;
import anonymous.tlsattacker.tls.config.GeneralConfig;
import anonymous.tlsattacker.tls.config.ServerCommandConfig;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.transport.TransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a generic Man in the Middle attack against a target server and a
 * client.
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ManInTheMiddleAttack extends Attacker<ManInTheMiddleAttackCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(ManInTheMiddleAttack.class);

    public ManInTheMiddleAttack(ManInTheMiddleAttackCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler clientConfigHandler) {
	// create server objects
	ServerCommandConfig serverCommandConfig = new ServerCommandConfig();
	serverCommandConfig.setPort(config.getPort());
	serverCommandConfig.setCipherSuites(config.getCipherSuites());
	serverCommandConfig.setKeystore(config.getKeystore());
	serverCommandConfig.setPassword(config.getPassword());
	serverCommandConfig.setAlias(config.getAlias());
	serverCommandConfig.setWorkflowTraceType(config.getWorkflowTraceType());

	GeneralConfig generalConfig = new GeneralConfig();
	ConfigHandler serverConfigHandler = ConfigHandlerFactory.createConfigHandler("server");
	serverConfigHandler.initialize(generalConfig);
	TransportHandler serverTransportHandler = serverConfigHandler.initializeTransportHandler(serverCommandConfig);
	TlsContext serverTlsContext = serverConfigHandler.initializeTlsContext(serverCommandConfig);

	// create client objects
	TransportHandler clientTransportHandler = clientConfigHandler.initializeTransportHandler(config);
	TlsContext clientTlsContext = clientConfigHandler.initializeTlsContext(config);

	// load workflow into the tlsContext objects
	RSAExampleMitMWorkflowConfiguration clientwf = new RSAExampleMitMWorkflowConfiguration(clientTlsContext, config);
	clientwf.createWorkflow();

	RSAExampleMitMWorkflowConfiguration serverwf = new RSAExampleMitMWorkflowConfiguration(serverTlsContext, config);
	serverwf.createWorkflow();

	// should the whole workflow trace be modified
	boolean mod = config.isModify();

	MitMWorkflowExecutor mitmWorkflowExecutor = new MitMWorkflowExecutor(clientTransportHandler,
		serverTransportHandler, clientTlsContext, serverTlsContext, mod);

	mitmWorkflowExecutor.executeWorkflow();

	clientTransportHandler.closeConnection();
	serverTransportHandler.closeConnection();
    }
}
