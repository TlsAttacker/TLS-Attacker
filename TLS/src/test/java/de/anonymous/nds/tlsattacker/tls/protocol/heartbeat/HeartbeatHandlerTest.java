/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.heartbeat;

import anonymous.tlsattacker.tls.protocol.heartbeat.HeartbeatHandler;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import anonymous.tlsattacker.tls.constants.HeartbeatMessageType;
import anonymous.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 * @author anonymous Pfützenreuter <anonymous.pfuetzenreuter@anonymous>
 */
public class HeartbeatHandlerTest {

    HeartbeatHandler heartbeatHandler;

    public HeartbeatHandlerTest() {
	TlsContext context = new TlsContext();
	context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
	context.setProtocolVersion(ProtocolVersion.TLS12);
	heartbeatHandler = new HeartbeatHandler(context);
    }

    /**
     * Test of prepareMessageAction method, of class HeartbeatHandler.
     */
    @Test
    public void testPrepareMessageAction() {
	heartbeatHandler.initializeProtocolMessage();

	byte[] result = heartbeatHandler.prepareMessageAction();
	int payload_length = ArrayConverter.bytesToInt(Arrays.copyOfRange(result, 1, 3));

	assertNotNull("Confirm prepareMessageAction didn't return 'NULL'.", result);
	assertEquals("Confirm message is a request.", HeartbeatMessageType.HEARTBEAT_REQUEST.getValue(), result[0]);
	assertTrue("Confirm message is not bigger than the max. message size"
		+ "according to the limits set by HeartbeatHandler class.",
		result.length <= HeartbeatHandler.MAX_PADDING_LENGTH + HeartbeatHandler.MAX_PAYLOAD_LENGTH + 3);
	assertTrue("Confirm message meets the minimum message size according "
		+ "to the limits set by HeatbeatHandler class.",
		result.length >= HeartbeatHandler.MIN_PADDING_LENGTH + 3);
	assertTrue("Confirm payload length is at least 0 byte.", payload_length >= 0);
	assertTrue("Confirm payload length meets the limit set by HeatbeatHandler class",
		payload_length <= HeartbeatHandler.MAX_PAYLOAD_LENGTH);
	assertTrue("Confirm padding meets the minumum padding length set by " + "HeatbeatHandler class", result.length
		- (payload_length + 3) >= HeartbeatHandler.MIN_PADDING_LENGTH);
	assertTrue("Confirm padding length doesn't exceed it's max. length "
		+ "according to the limits set by HeatbeatHandler class",
		result.length - (payload_length + 3) <= HeartbeatHandler.MAX_PADDING_LENGTH);
    }

    /**
     * Test of parseMessageAction method, of class HeartbeatHandler.
     */
    @Test
    public void testParseMessageAction() {
	heartbeatHandler.initializeProtocolMessage();

	byte[] result = heartbeatHandler.prepareMessageAction();
	int pointer = heartbeatHandler.parseMessage(result, 0);

	assertEquals(result.length, pointer);
	assertEquals((Byte) HeartbeatMessageType.HEARTBEAT_REQUEST.getValue(), heartbeatHandler.getProtocolMessage()
		.getHeartbeatMessageType().getValue());

    }

}
