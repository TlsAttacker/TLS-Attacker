/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls;

import com.beust.jcommander.JCommander;
import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.config.GeneralConfig;
import anonymous.tlsattacker.tls.config.CommandConfig;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.config.ConfigHandlerFactory;
import anonymous.tlsattacker.tls.config.ServerCommandConfig;
import anonymous.tlsattacker.tls.config.WorkflowTraceSerializer;
import anonymous.tlsattacker.tls.workflow.SessionResumptionWorkflowConfiguration;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.transport.TransportHandler;
import java.io.FileOutputStream;

/**
 * @author anonymous anonymous (anonymous.anonymous@anonymous)
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class Main {

    public static void main(String[] args) throws Exception {

	GeneralConfig generalConfig = new GeneralConfig();
	JCommander jc = new JCommander(generalConfig);

	ServerCommandConfig server = new ServerCommandConfig();
	jc.addCommand(ServerCommandConfig.COMMAND, server);
	ClientCommandConfig client = new ClientCommandConfig();
	jc.addCommand(ClientCommandConfig.COMMAND, client);

	jc.parse(args);

	if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
	    jc.usage();
	    return;
	}

	CommandConfig config;
	if (jc.getParsedCommand().equals(ServerCommandConfig.COMMAND)) {
	    config = server;
	} else {
	    config = client;
	}

	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler(jc.getParsedCommand());
	configHandler.initialize(generalConfig);

	if (configHandler.printHelpForCommand(jc, config)) {
	    return;
	}

	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	workflowExecutor.executeWorkflow();

	// if (config.isVerifyWorkflowCorrectness()) {
	// workflowExecutor.checkConfiguredProtocolMessagesOrder();
	// }

	transportHandler.closeConnection();

	// setting and executing the session resumption workflow trace
	if (config.isSessionResumption()) {
	    TransportHandler transportHandlerSR = configHandler.initializeTransportHandler(config);

	    SessionResumptionWorkflowConfiguration SRworkflow = new SessionResumptionWorkflowConfiguration(tlsContext,
		    config);
	    SRworkflow.createWorkflow();

	    WorkflowExecutor workflowExecutorSR = configHandler.initializeWorkflowExecutor(transportHandlerSR,
		    tlsContext);

	    workflowExecutorSR.executeWorkflow();

	    transportHandlerSR.closeConnection();
	}

	if (config.getWorkflowOutput() != null && !config.getWorkflowOutput().isEmpty()) {
	    FileOutputStream fos = new FileOutputStream(config.getWorkflowOutput());
	    WorkflowTraceSerializer.write(fos, tlsContext.getWorkflowTrace());
	}
    }
}
