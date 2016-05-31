/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeHandler;
import anonymous.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeHandler;
import anonymous.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import anonymous.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import org.bouncycastle.util.BigIntegers;
import org.junit.Assert;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class DHClientKeyExchangeHandlerTest {

    static BigInteger publicKey = new BigInteger(
	    "6b7123248ca29efc8baea75d4f4321f58c072281e9f8217ae19750b5000714b24aa603ed61eb"
		    + "2c6d4a047922a0ba48dcfc57552ad137a39c1078e92a2da74b19", 16);

    DHClientKeyExchangeHandler handler;

    DHEServerKeyExchangeHandler skeHandler;

    public DHClientKeyExchangeHandlerTest() {
	TlsContext context = new TlsContext();
	context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
	context.setProtocolVersion(ProtocolVersion.TLS12);
	handler = new DHClientKeyExchangeHandler(context);

	// initialize tls context with dh parameters
	skeHandler = new DHEServerKeyExchangeHandler(context);
	byte[] serverKeyExchangeBytes = DHEServerKeyExchangeHandlerTest.testServerKeyExchangeDSA;
	skeHandler.initializeProtocolMessage();
	skeHandler.parseMessageAction(serverKeyExchangeBytes, 0);
    }

    /**
     * Test of prepareMessageAction method, of class
     * ECDHClientKeyExchangeHandler.
     */
    @Test
    public void testPrepareMessage() {
	handler.initializeProtocolMessage();

	DHClientKeyExchangeMessage message = (DHClientKeyExchangeMessage) handler.getProtocolMessage();
	ModifiableBigInteger y = new ModifiableBigInteger();
	y.setModification(BigIntegerModificationFactory.explicitValue(publicKey));
	message.setY(y);

	byte[] result = handler.prepareMessageAction();

	assertEquals("Message type must be ClientKeyExchange", HandshakeMessageType.CLIENT_KEY_EXCHANGE,
		message.getHandshakeMessageType());

	byte[] serializedPublicKey = BigIntegers.asUnsignedByteArray(publicKey);
	byte[] expected = ArrayConverter.concatenate(new byte[] { 0x10, 0x00, 0x00, (byte) 0x42, 0x00, (byte) 0x40 },
		serializedPublicKey);

	Assert.assertArrayEquals(expected, result);
    }

    /**
     * Test of parseMessageAction method, of class DHClientKeyExchangeHandler.
     */
    @Test
    public void testParseMessage() {
	// todo
    }
}
