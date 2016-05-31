/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.tls.protocol.handshake.CertificateRequestHandler;
import anonymous.tlsattacker.tls.constants.ClientCertificateType;
import anonymous.tlsattacker.tls.constants.HandshakeByteLength;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.constants.HashAlgorithm;
import anonymous.tlsattacker.tls.constants.SignatureAlgorithm;
import anonymous.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
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
public class CertificateRequestHandlerTest {

    private CertificateRequestHandler handler;

    public CertificateRequestHandlerTest() {
	handler = new CertificateRequestHandler(new TlsContext());
    }

    /**
     * Test of prepareMessageAction method, of class CertificateRequestHandler.
     */
    @Test
    public void testPrepareMessageAction() {
	handler.setProtocolMessage(new CertificateRequestMessage());

	CertificateRequestMessage message = (CertificateRequestMessage) handler.getProtocolMessage();

	byte[] returned = handler.prepareMessageAction();
	byte[] expected = ArrayConverter.concatenate(
		new byte[] { HandshakeMessageType.CERTIFICATE_REQUEST.getValue() }, new byte[] { 0x00, 0x00, 0x12 },
		new byte[] { 0x01 }, message.getClientCertificateTypes().getValue(), new byte[] { 0x00, 0x0C }, message
			.getSignatureHashAlgorithms().getValue(), new byte[] { 0x00, 0x00 });

	assertNotNull("Confirm function didn't return 'NULL'", returned);
	assertArrayEquals("Confirm returned message equals the expected message", expected, returned);

    }

    /**
     * Test of parseMessageAction method, of class CertificateRequestHandler.
     */
    @Test
    public void testParseMessageAction() {
	handler.initializeProtocolMessage();

	byte[] inputBytes = { HandshakeMessageType.CERTIFICATE_REQUEST.getValue(), 0x00, 0x00, 0x07, 0x01,
		ClientCertificateType.RSA_SIGN.getValue(), 0x00, 0x02 };
	byte[] sigHashAlg = new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA512).getByteValue();
	inputBytes = ArrayConverter.concatenate(inputBytes, sigHashAlg, new byte[] { 0x00, 0x00 });
	int endPointer = handler.parseMessageAction(inputBytes, 0);
	CertificateRequestMessage message = (CertificateRequestMessage) handler.getProtocolMessage();

	assertNotNull("Confirm endPointer is not 'NULL'", endPointer);
	assertEquals("Confirm actual message length", endPointer, 12);
	assertEquals("Confirm message type", HandshakeMessageType.CERTIFICATE_REQUEST,
		message.getHandshakeMessageType());
	assertTrue("Confirm certificate type count", message.getClientCertificateTypesCount().getValue() == 1);
	assertEquals("Confirm certificate type", ClientCertificateType.RSA_SIGN.getValue(), message
		.getClientCertificateTypes().getValue()[0]);
	assertTrue("Confirm SignatureAndHashAlgorithm count",
		message.getSignatureHashAlgorithmsLength().getValue() == 2);
	assertArrayEquals("Confirm SignatureAndHashAlgorithm type", sigHashAlg, message.getSignatureHashAlgorithms()
		.getValue());
	assertTrue("Confirm DistinguishedName is empty", message.getDistinguishedNamesLength().getValue() == 0);
    }

}
