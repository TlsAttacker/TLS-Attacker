/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.constants;

import anonymous.tlsattacker.dtls.protocol.handshake.HelloVerifyRequestHandler;
import anonymous.tlsattacker.tls.protocol.ProtocolMessageHandler;
import anonymous.tlsattacker.tls.protocol.ProtocolMessageHandlerBearer;
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloHandler;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateHandler;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateRequestHandler;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateVerifyHandler;
import anonymous.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeHandler;
import anonymous.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeHandler;
import anonymous.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeHandler;
import anonymous.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeHandler;
import anonymous.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeHandler;
import anonymous.tlsattacker.tls.protocol.handshake.FinishedHandler;
import anonymous.tlsattacker.tls.protocol.handshake.HelloRequestHandler;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloDoneHandler;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloHandler;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import java.util.HashMap;
import java.util.Map;

/**
 * Also called Handshake Type
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public enum HandshakeMessageType implements ProtocolMessageHandlerBearer {

    HELLO_REQUEST((byte) 0) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new HelloRequestHandler(tlsContext);
	}
    },
    CLIENT_HELLO((byte) 1) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new ClientHelloHandler(tlsContext);
	}
    },
    SERVER_HELLO((byte) 2) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new ServerHelloHandler(tlsContext);
	}
    },
    HELLO_VERIFY_REQUEST((byte) 3) {
	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new HelloVerifyRequestHandler(tlsContext);
	}
    },
    NEW_SESSION_TICKET((byte) 4) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    throw new UnsupportedOperationException("Not supported yet.");
	}
    },
    CERTIFICATE((byte) 11) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new CertificateHandler(tlsContext);
	}
    },
    SERVER_KEY_EXCHANGE((byte) 12) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    CipherSuite cs = tlsContext.getSelectedCipherSuite();
	    switch (AlgorithmResolver.getKeyExchangeAlgorithm(cs)) {
		case EC_DIFFIE_HELLMAN:
		    return new ECDHEServerKeyExchangeHandler(tlsContext);
		case DHE_DSS:
		case DHE_RSA:
		case DH_ANON:
		case DH_DSS:
		case DH_RSA:
		    return new DHEServerKeyExchangeHandler(tlsContext);
		default:
		    throw new UnsupportedOperationException("Not supported yet.");
	    }
	}
    },
    CERTIFICATE_REQUEST((byte) 13) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new CertificateRequestHandler(tlsContext);
	}
    },
    SERVER_HELLO_DONE((byte) 14) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new ServerHelloDoneHandler(tlsContext);
	}
    },
    CERTIFICATE_VERIFY((byte) 15) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new CertificateVerifyHandler(tlsContext);
	}
    },
    CLIENT_KEY_EXCHANGE((byte) 16) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    CipherSuite cs = tlsContext.getSelectedCipherSuite();
	    switch (AlgorithmResolver.getKeyExchangeAlgorithm(cs)) {
		case RSA:
		    return new RSAClientKeyExchangeHandler(tlsContext);
		case EC_DIFFIE_HELLMAN:
		    return new ECDHClientKeyExchangeHandler(tlsContext);
		case DHE_DSS:
		case DHE_RSA:
		case DH_ANON:
		case DH_DSS:
		case DH_RSA:
		    return new DHClientKeyExchangeHandler(tlsContext);
		default:
		    throw new UnsupportedOperationException("Not supported yet.");
	    }
	}
    },
    FINISHED((byte) 20) {

	@Override
	ProtocolMessageHandler getMessageHandler(TlsContext tlsContext) {
	    return new FinishedHandler(tlsContext);
	}
    };

    private byte value;

    private ConnectionEnd messageSender;

    private static final Map<Byte, HandshakeMessageType> MAP;

    private HandshakeMessageType(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (HandshakeMessageType cm : HandshakeMessageType.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static HandshakeMessageType getMessageType(byte value) {
	return MAP.get(value);
    }

    public static HandshakeMessageType getMessageType(byte value, ConnectionEnd messageSender) {
	HandshakeMessageType type = MAP.get(value);
	type.messageSender = messageSender;
	return type;
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }

    public final String getName() {
	return this.name();
    }

    abstract ProtocolMessageHandler getMessageHandler(TlsContext tlsContext);

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
	return getMessageHandler(tlsContext);
    }
}
