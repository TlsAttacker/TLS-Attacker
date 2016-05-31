/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.impl;

import anonymous.tlsattacker.tls.Attacker;
import anonymous.tlsattacker.attacks.config.PoodleCommandConfig;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.exceptions.WorkflowExecutionException;
import anonymous.tlsattacker.tls.protocol.alert.AlertMessage;
import anonymous.tlsattacker.tls.protocol.application.ApplicationMessage;
import anonymous.tlsattacker.tls.record.Record;
import anonymous.tlsattacker.tls.util.LogLevel;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.TlsContextAnalyzer;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.transport.TransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a poodle attack. It logs an error in case the tested server is
 * vulnerable to poodle.
 * 
 * @author anonymous anonymous (anonymous.anonymous@anonymous)
 */
public class PoodleAttack extends Attacker<PoodleCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(PoodleAttack.class);

    public PoodleAttack(PoodleCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();

	ModifiableByteArray padding = new ModifiableByteArray();
	// we xor just the first byte in the padding
	// if the padding was {0x02, 0x02, 0x02}, it becomes {0x03, 0x02, 0x02}
	VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] { 1 }, 0);
	padding.setModification(modifier);

	ApplicationMessage applicationMessage = new ApplicationMessage(ConnectionEnd.CLIENT);
	Record r = new Record();
	r.setPadding(padding);
	applicationMessage.addRecord(r);

	AlertMessage allertMessage = new AlertMessage(ConnectionEnd.SERVER);

	trace.getProtocolMessages().add(applicationMessage);
	trace.getProtocolMessages().add(allertMessage);

	try {
	    workflowExecutor.executeWorkflow();
	} catch (WorkflowExecutionException ex) {
	    LOGGER.info("Not possible to finalize the defined workflow: {}", ex.getLocalizedMessage());
	}

	TlsContextAnalyzer.AnalyzerResponse analyzerResponse = TlsContextAnalyzer
		.containsAlertAfterModifiedMessage(tlsContext);
	if (analyzerResponse == TlsContextAnalyzer.AnalyzerResponse.ALERT) {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT,
		    "NOT Vulnerable. The modified message padding was identified, the server correctly responds with an alert message");
	} else if (analyzerResponse == TlsContextAnalyzer.AnalyzerResponse.NO_ALERT) {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT,
		    "Vulnerable(?). The modified message padding was not identified, the server does NOT respond with an alert message");
	} else {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT,
		    "Vulnerable(?). The protocol message flow was incomplete, analyze the message flow");
	}

	tlsContexts.add(tlsContext);

	transportHandler.closeConnection();
    }
}
