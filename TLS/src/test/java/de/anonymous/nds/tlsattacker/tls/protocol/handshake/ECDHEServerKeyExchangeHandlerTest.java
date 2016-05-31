/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.tls.constants.EllipticCurveType;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.constants.HashAlgorithm;
import anonymous.tlsattacker.tls.constants.NamedCurve;
import anonymous.tlsattacker.tls.constants.SignatureAlgorithm;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.ArrayConverter;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for ECDHE key exchange handler, with values from wireshark
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ECDHEServerKeyExchangeHandlerTest {

    static byte[] testServerKeyExchangeECDSA = ArrayConverter
	    .hexStringToByteArray("0c0000d003000e910404a9c2a82e8f7e90e11c26035f93dae74553334b074484895a7560a5e949251d4c"
		    + "77ebfc4443bb0d9cfe204ca3bd67a8074f32c0ff865fb434f0647c3f1b10072b822c65f924595302f38a1a34dfaaec91"
		    + "e9702aa5658cb506f6d790aa72a3edea5677a81ea3c6248802b23e88de60659bad8c34f67a4852ec985cdb092ef85b59"
		    + "2861372dce0b3f82e7aa76c50b8afe060300373035021876494098e491e52572458f37f47a1f99701e7ae3a313282202"
		    + "1900b6c9e009bb751dee939b4b50f55f3d9f167283d3f4155f50");

    static byte[] testServerKeyExchangeRSA = ArrayConverter
	    .hexStringToByteArray("0c00011903000e9104053bca98c5a607ab9cb2449c9467c8001d891524383351066c903c62477c4d0c8b"
		    + "b370e2c1e96caf1500de8fa9d5c85b82a0be5bb868f7e6e5a91cbfa3fc82c7864eab5bb508c23202c5217297dcd65857"
		    + "8e48ec0c8b4a094493414f74315557f6daf25eba4c3c4006a64e9ed18788539c5e6a4abeeba1167424c106fea33ff2a6"
		    + "5ed756220d4f62b4c7879ba09d85150601008011d246b6b74076f697d45447dadd6aeaaef298fc8fa48a0237dac8639a"
		    + "6e3bfeffae3bd2ee6a4f786ee9f76b52c7df82f3b9d23b49f8934f29ea3c1f2dc4a016066ab9e05277ba4a41e85a38d3"
		    + "5c0537155bc0f386587d61f819970c7ae7918940a05308758253deb71f8d7d18fd540e372dba7829f6d86a38c20e60f5"
		    + "0500b1");

    ECDHEServerKeyExchangeHandler handler;

    public ECDHEServerKeyExchangeHandlerTest() {
	handler = new ECDHEServerKeyExchangeHandler(new TlsContext());
    }

    /**
     * Test of parseMessageAction method, of class
     * ECDHEServerKeyExchangeHandler.
     */
    @Test
    public void testParseMessageECDSA() {
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessageAction(testServerKeyExchangeECDSA, 0);
	ECDHEServerKeyExchangeMessage message = (ECDHEServerKeyExchangeMessage) handler.getProtocolMessage();

	assertEquals("Message type must be ServerKeyExchange", HandshakeMessageType.SERVER_KEY_EXCHANGE,
		message.getHandshakeMessageType());
	assertEquals("Message length must be 208", new Integer(208), message.getLength().getValue());
	assertEquals("Curve Type must be named curve", EllipticCurveType.NAMED_CURVE,
		EllipticCurveType.getCurveType(message.getCurveType().getValue()));
	assertEquals("Named Curve must be sect571r1", NamedCurve.SECT571R1,
		NamedCurve.getNamedCurve(message.getNamedCurve().getValue()));
	assertEquals("Public key length is 145", new Integer(145), message.getPublicKeyLength().getValue());
	assertEquals("Hash must be SHA512", HashAlgorithm.SHA512,
		HashAlgorithm.getHashAlgorithm(message.getHashAlgorithm().getValue()));
	assertEquals("Signature must be ECDSA", SignatureAlgorithm.ECDSA,
		SignatureAlgorithm.getSignatureAlgorithm(message.getSignatureAlgorithm().getValue()));
	assertEquals("Signature length must be 55", new Integer(55), message.getSignatureLength().getValue());

	assertEquals("The pointer has to return the length of the protocol message", testServerKeyExchangeECDSA.length,
		endPointer);
    }

    /**
     * Test of parseMessageAction method, of class
     * ECDHEServerKeyExchangeHandler.
     */
    @Test
    public void testParseMessageRSA() {
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessageAction(testServerKeyExchangeRSA, 0);
	ECDHEServerKeyExchangeMessage message = (ECDHEServerKeyExchangeMessage) handler.getProtocolMessage();

	assertEquals("Message type must be ServerKeyExchange", HandshakeMessageType.SERVER_KEY_EXCHANGE,
		message.getHandshakeMessageType());
	assertEquals("Message length must be 281", new Integer(281), message.getLength().getValue());
	assertEquals("Curve Type must be named curve", EllipticCurveType.NAMED_CURVE,
		EllipticCurveType.getCurveType(message.getCurveType().getValue()));
	assertEquals("Named Curve must be sect571r1", NamedCurve.SECT571R1,
		NamedCurve.getNamedCurve(message.getNamedCurve().getValue()));
	assertEquals("Public key length is 145", new Integer(145), message.getPublicKeyLength().getValue());
	assertEquals("Hash must be SHA512", HashAlgorithm.SHA512,
		HashAlgorithm.getHashAlgorithm(message.getHashAlgorithm().getValue()));
	assertEquals("Signature must be RSA", SignatureAlgorithm.RSA,
		SignatureAlgorithm.getSignatureAlgorithm(message.getSignatureAlgorithm().getValue()));
	assertEquals("Signature length must be 128", new Integer(128), message.getSignatureLength().getValue());

	assertEquals("The pointer has to return the length of the protocol message", testServerKeyExchangeRSA.length,
		endPointer);
    }

    @Test
    public void testIsCorrectProtocolMessage() {
	ECDHEServerKeyExchangeMessage sem = new ECDHEServerKeyExchangeMessage();
	assertTrue(handler.isCorrectProtocolMessage(sem));

	CertificateMessage cm = new CertificateMessage();
	assertFalse(handler.isCorrectProtocolMessage(cm));
    }
}
