/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.alert;

import anonymous.tlsattacker.tls.protocol.alert.AlertHandler;
import anonymous.tlsattacker.tls.constants.AlertDescription;
import anonymous.tlsattacker.tls.constants.AlertLevel;
import anonymous.tlsattacker.tls.protocol.alert.AlertMessage;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class AlertHandlerTest {

    /**
     * Test of prepareMessageAction method, of class AlertHandler.
     */
    @Test
    public void testPrepareMessageAction() {
	AlertHandler handler = new AlertHandler(new TlsContext());
	AlertMessage message = new AlertMessage();
	message.setConfig(AlertLevel.FATAL, AlertDescription.UNKNOWN_CA);
	handler.setProtocolMessage(message);
	byte[] result = handler.prepareMessageAction();
	assertEquals(AlertLevel.FATAL.getValue(), result[0]);
	assertEquals(AlertDescription.UNKNOWN_CA.getValue(), result[1]);
    }

    /**
     * Test of parseMessageAction method, of class AlertHandler.
     */
    @Test
    public void testParseMessageAction() {
	AlertHandler handler = new AlertHandler(new TlsContext());
	handler.setProtocolMessage(new AlertMessage());
	byte[] message = { 3, 3 };
	int pointer = handler.parseMessageAction(message, 0);
	assertEquals(2, pointer);
	assertEquals(3, handler.getProtocolMessage().getLevel().getValue().byteValue());
	assertEquals(3, handler.getProtocolMessage().getDescription().getValue().byteValue());
    }

}
