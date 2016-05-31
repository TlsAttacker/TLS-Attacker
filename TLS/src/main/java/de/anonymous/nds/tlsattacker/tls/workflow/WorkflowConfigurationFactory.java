/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.tls.config.CommandConfig;
import anonymous.tlsattacker.tls.constants.AlgorithmResolver;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.ProtocolMessageTypeHolder;
import anonymous.tlsattacker.tls.constants.MaxFragmentLength;
import anonymous.tlsattacker.tls.constants.NameType;
import anonymous.tlsattacker.tls.protocol.extension.ECPointFormatExtensionMessage;
import anonymous.tlsattacker.tls.protocol.extension.EllipticCurvesExtensionMessage;
import anonymous.tlsattacker.tls.protocol.extension.HeartbeatExtensionMessage;
import anonymous.tlsattacker.tls.protocol.extension.MaxFragmentLengthExtensionMessage;
import anonymous.tlsattacker.tls.protocol.extension.ServerNameIndicationExtensionMessage;
import anonymous.tlsattacker.tls.protocol.extension.SignatureAndHashAlgorithmsExtensionMessage;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import java.util.LinkedList;
import java.util.List;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public abstract class WorkflowConfigurationFactory {

    /**
     * This method constructs an instance of WorkflowConfigurationFactory based
     * on the used CommandConfig parameter. It can be either a dynamic
     * configuration factory or a static configuration factory, with a
     * predefined list of protocol messages.
     * 
     * The list of protocol messages is generated based on the first ciphersuite
     * in the ciphersuite list.
     * 
     * @param config
     * @return
     */
    public static WorkflowConfigurationFactory createInstance(CommandConfig config) {
	if (config.isDynamicWorkflow()) {
	    // TODO create a factory for dynamic workflow
	    throw new UnsupportedOperationException("This configuration is not " + "supported yet");
	} else {
	    // we decide based on the first cipher how to construct a handshake.
	    CipherSuite cs = config.getCipherSuites().get(0);
	    switch (AlgorithmResolver.getKeyExchangeAlgorithm(cs)) {
		case RSA:
		    if (config.getProtocolVersion() == ProtocolVersion.DTLS10
			    || config.getProtocolVersion() == ProtocolVersion.DTLS12) {
			return new DtlsRsaWorkflowConfigurationFactory(config);
		    } else {
			return new RsaWorkflowConfigurationFactory(config);
		    }
		case EC_DIFFIE_HELLMAN:
		    if (config.getProtocolVersion() == ProtocolVersion.DTLS10
			    || config.getProtocolVersion() == ProtocolVersion.DTLS12) {
			return new DtlsEcdhWorkflowConfigurationFactory(config);
		    } else {
			return new ECDHWorkflowConfigurationFactory(config);
		    }
		case DHE_DSS:
		case DHE_RSA:
		case DH_ANON:
		case DH_DSS:
		case DH_RSA:
		    if (config.getProtocolVersion() == ProtocolVersion.DTLS10
			    || config.getProtocolVersion() == ProtocolVersion.DTLS12) {
			return new DtlsDhWorkflowConfigurationFactory(config);
		    } else {
			return new DHWorkflowConfigurationFactory(config);
		    }
		default:
		    throw new UnsupportedOperationException("This configuration is not " + "supported yet");
	    }
	}
    }

    /**
     * Creates a basic TLS context with a single ClientHello message
     * 
     * @return
     */
    public abstract TlsContext createClientHelloTlsContext();

    /**
     * Creates a basic TLS context with a TLS handshake messages
     * 
     * @return
     */
    public abstract TlsContext createHandshakeTlsContext();

    /**
     * Creates an extended TLS context including an application data and
     * heartbeat messages
     * 
     * @return
     */
    public abstract TlsContext createFullTlsContext();

    /**
     * Creates a full TLS context with additional application data
     * ServerResponse
     * 
     * @return
     */
    public TlsContext createFullServerResponseTlsContext() {
	return createFullTlsContext();
    }

    /**
     * Initializes ClientHello extensions
     * 
     * @param config
     * @param ch
     */
    public static void initializeClientHelloExtensions(CommandConfig config, ClientHelloMessage ch) {
	if (config.getNamedCurves() != null && !config.getNamedCurves().isEmpty()) {
	    EllipticCurvesExtensionMessage ecc = new EllipticCurvesExtensionMessage();
	    ecc.setSupportedCurvesConfig(config.getNamedCurves());
	    ch.addExtension(ecc);
	}

	if (config.getPointFormats() != null && !config.getPointFormats().isEmpty()) {
	    ECPointFormatExtensionMessage pfc = new ECPointFormatExtensionMessage();
	    pfc.setPointFormatsConfig(config.getPointFormats());
	    ch.addExtension(pfc);
	}

	if (config.getHeartbeatMode() != null) {
	    HeartbeatExtensionMessage hem = new HeartbeatExtensionMessage();
	    hem.setHeartbeatModeConfig(config.getHeartbeatMode());
	    ch.addExtension(hem);
	}

	if (config.getServerName() != null) {
	    ServerNameIndicationExtensionMessage sni = new ServerNameIndicationExtensionMessage();
	    sni.setNameTypeConfig(NameType.HOST_NAME);
	    sni.setServerNameConfig(config.getServerName());
	    ch.addExtension(sni);
	}

	if (config.getMaxFragmentLength() != null) {
	    MaxFragmentLengthExtensionMessage mle = new MaxFragmentLengthExtensionMessage();
	    mle.setMaxFragmentLengthConfig(MaxFragmentLength.getMaxFragmentLength(config.getMaxFragmentLength()
		    .byteValue()));
	    ch.addExtension(mle);
	}

	if (config.getSignatureAndHashAlgorithms() != null) {
	    SignatureAndHashAlgorithmsExtensionMessage sae = new SignatureAndHashAlgorithmsExtensionMessage();
	    sae.setSignatureAndHashAlgorithmsConfig(config.getSignatureAndHashAlgorithms());
	    ch.addExtension(sae);
	}
    }

    /**
     * Initializes the preconfigured protocol message order according to the
     * workflow trace. This protocol message order can be used to compare the
     * configured and real message order.
     * 
     * @param context
     */
    public static void initializeProtocolMessageOrder(TlsContext context) {
	List<ProtocolMessageTypeHolder> configuredProtocolMessageOrder = new LinkedList<>();
	for (ProtocolMessage pm : context.getWorkflowTrace().getProtocolMessages()) {
	    ProtocolMessageTypeHolder pmth = new ProtocolMessageTypeHolder(pm);
	    configuredProtocolMessageOrder.add(pmth);
	}
	context.setPreconfiguredProtocolMessages(configuredProtocolMessageOrder);
    }

    /**
     * 
     * 
     * @param context
     * @param protocolMessages
     */
    public static void appendProtocolMessagesToWorkflow(TlsContext context, List<ProtocolMessage> protocolMessages) {
	List<ProtocolMessage> configured = context.getWorkflowTrace().getProtocolMessages();
	for (ProtocolMessage pm : protocolMessages) {
	    configured.add(pm);
	}
	initializeProtocolMessageOrder(context);
    }
}
