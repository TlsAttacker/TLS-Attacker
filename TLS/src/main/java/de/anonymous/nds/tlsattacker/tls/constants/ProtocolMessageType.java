/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.constants;

import anonymous.tlsattacker.tls.protocol.ProtocolMessageHandler;
import anonymous.tlsattacker.tls.protocol.alert.AlertHandler;
import anonymous.tlsattacker.tls.protocol.application.ApplicationHandler;
import anonymous.tlsattacker.tls.protocol.ccs.ChangeCipherSpecHandler;
import anonymous.tlsattacker.tls.protocol.heartbeat.HeartbeatHandler;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public enum ProtocolMessageType {

    CHANGE_CIPHER_SPEC((byte) 20),
    ALERT((byte) 21),
    HANDSHAKE((byte) 22),
    APPLICATION_DATA((byte) 23),
    HEARTBEAT((byte) 24);

    private static final Logger LOGGER = LogManager.getLogger(ProtocolMessageType.class);

    private byte value;

    private static final Map<Byte, ProtocolMessageType> MAP;

    private ProtocolMessageType(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (ProtocolMessageType cm : ProtocolMessageType.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static ProtocolMessageType getContentType(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }

    public ProtocolMessageHandler getProtocolMessageHandler(byte value, TlsContext tlsContext) {
	ProtocolMessageHandler pmh = null;
	LOGGER.debug("Trying to get a protocol message handler for the following content type: {}", this);
	switch (this) {
	    case HANDSHAKE:
		HandshakeMessageType hmt = HandshakeMessageType.getMessageType(value);
		LOGGER.debug("Trying to get a protocol message handler for the following handshake message: {}", hmt);
		pmh = hmt.getProtocolMessageHandler(tlsContext);
		break;
	    case CHANGE_CIPHER_SPEC:
		pmh = new ChangeCipherSpecHandler(tlsContext);
		break;
	    case ALERT:
		pmh = new AlertHandler(tlsContext);
		break;
	    case APPLICATION_DATA:
		pmh = new ApplicationHandler(tlsContext);
		break;
	    case HEARTBEAT:
		pmh = new HeartbeatHandler(tlsContext);
		break;
	}
	if (pmh == null) {
	    throw new UnsupportedOperationException("Not supported yet.");
	}
	return pmh;
    }
}
