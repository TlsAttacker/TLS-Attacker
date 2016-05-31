/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.tls.protocol.handshake.CertificateVerifyHandler;
import anonymous.tlsattacker.tls.constants.ClientCertificateType;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.constants.HashAlgorithm;
import anonymous.tlsattacker.tls.constants.SignatureAlgorithm;
import anonymous.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class CertificateVerifyHandlerTest {

    CertificateVerifyHandler handler;

    TlsContext tlsContext;

    public CertificateVerifyHandlerTest() {
	tlsContext = new TlsContext();
	handler = new CertificateVerifyHandler(tlsContext);
    }

    /**
     * Test of prepareMessageAction method, of class CertificateVerifyHandler.
     */
    @Test
    public void testPrepareMessageAction() {
	// todo
    }

    /**
     * Test of parseMessageAction method, of class CertificateVerifyHandler.
     */
    @Test
    public void testParseMessageAction() {

	handler.initializeProtocolMessage();

	byte[] inputBytes = { HandshakeMessageType.CERTIFICATE_VERIFY.getValue(), 0x00, 0x00, 0x09 };
	byte[] sigHashAlg = { HashAlgorithm.SHA512.getValue(), SignatureAlgorithm.RSA.getValue() };
	inputBytes = ArrayConverter.concatenate(inputBytes, sigHashAlg, new byte[] { 0x00, 0x05 }, new byte[] { 0x25,
		0x26, 0x27, 0x28, 0x29 });
	int endPointer = handler.parseMessageAction(inputBytes, 0);
	CertificateVerifyMessage message = (CertificateVerifyMessage) handler.getProtocolMessage();

	assertNotNull("Confirm endPointer is not 'NULL'", endPointer);
	assertEquals("Confirm actual message length", endPointer, 13);
	assertEquals("Confirm message type", HandshakeMessageType.CERTIFICATE_VERIFY, message.getHandshakeMessageType());
	assertArrayEquals("Confirm SignatureAndHashAlgorithm type", sigHashAlg, message.getSignatureHashAlgorithm()
		.getValue());
	assertTrue("Confirm Signature Length", message.getSignatureLength().getValue() == 5);
	assertTrue("Confirm Signature",
		Arrays.equals(message.getSignature().getValue(), new byte[] { 0x25, 0x26, 0x27, 0x28, 0x29 }));

    }

}
