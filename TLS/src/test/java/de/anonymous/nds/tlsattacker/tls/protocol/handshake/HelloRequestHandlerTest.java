/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.ArrayConverter;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class HelloRequestHandlerTest {

    private HelloRequestHandler handler;

    public HelloRequestHandlerTest() {
	handler = new HelloRequestHandler(new TlsContext());
    }

    /**
     * Test of prepareMessageAction method, of class HelloRequestHandler.
     */
    @Test
    public void testPrepareMessageAction() {
	handler.setProtocolMessage(new HelloRequestMessage());

	HelloRequestMessage message = (HelloRequestMessage) handler.getProtocolMessage();

	byte[] returned = handler.prepareMessageAction();
	byte[] expected = ArrayConverter.concatenate(new byte[] { HandshakeMessageType.HELLO_REQUEST.getValue() },
		new byte[] { 0x00, 0x00, 0x00 });

	assertNotNull("Confirm function didn't return 'NULL'", returned);
	assertArrayEquals("Confirm returned message equals the expected message", expected, returned);
    }

    /**
     * Test of parseMessageAction method, of class HelloRequestHandler.
     */
    @Test
    public void testParseMessageAction() {
	byte[] helloRequestMsg = { 0x00, 0x00, 0x00, 0x00 };
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessage(helloRequestMsg, 0);
	HelloRequestMessage message = handler.getProtocolMessage();

	assertNotNull("Confirm that parseMessage didn't return 'NULL'", endPointer);
	assertEquals("Confirm expected message type: \"HelloRequest\"", HandshakeMessageType.HELLO_REQUEST,
		message.getHandshakeMessageType());
	assertEquals("Confirm expected message length of \"0\"", new Integer(0), message.getLength().getValue());
	assertEquals("Confirm the correct value of endPointer representing the " + "actual number of message bytes",
		helloRequestMsg.length, endPointer);
    }

}
