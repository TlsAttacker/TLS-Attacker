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
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 * @author anonymous Pfützenreuter - anonymous.pfuetzenreuter@anonymous
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ServerHelloDoneHandlerTest {

    private ServerHelloDoneHandler handler;

    public ServerHelloDoneHandlerTest() {
	handler = new ServerHelloDoneHandler(new TlsContext());
    }

    /**
     * Test of prepareMessageAction method, of class ServerHelloDoneHandler.
     */
    @Test
    public void testPrepareMessageAction() {
	handler.setProtocolMessage(new ServerHelloDoneMessage());

	ServerHelloDoneMessage message = (ServerHelloDoneMessage) handler.getProtocolMessage();

	byte[] returned = handler.prepareMessageAction();
	byte[] expected = ArrayConverter.concatenate(new byte[] { HandshakeMessageType.SERVER_HELLO_DONE.getValue() },
		new byte[] { 0x00, 0x00, 0x00 });

	assertNotNull("Confirm function didn't return 'NULL'", returned);
	assertArrayEquals("Confirm returned message equals the expected message", expected, returned);
    }

    /**
     * Test of parseMessageAction method, of class ServerHelloDoneHandler.
     */
    @Test
    public void testParseMessageAction() {
	byte[] serverHelloDoneMsg = { 0x0e, 0x00, 0x00, 0x00 };
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessage(serverHelloDoneMsg, 0);
	ServerHelloDoneMessage message = handler.getProtocolMessage();

	assertNotNull("Confirm that parseMessage didn't return 'NULL'", endPointer);
	assertEquals("Confirm expected message type: \"ServerHelloDone\"", HandshakeMessageType.SERVER_HELLO_DONE,
		message.getHandshakeMessageType());
	assertEquals("Confirm expected message length of \"0\"", new Integer(0), message.getLength().getValue());
	assertEquals("Confirm the correct value of endPointer representing the " + "actual number of message bytes",
		serverHelloDoneMsg.length, endPointer);
    }

}
