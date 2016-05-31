/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.ccs;

import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.crypto.TlsRecordBlockCipher;
import anonymous.tlsattacker.tls.exceptions.CryptoException;
import anonymous.tlsattacker.tls.protocol.ProtocolMessageHandler;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ChangeCipherSpecHandler extends ProtocolMessageHandler<ChangeCipherSpecMessage> {

    public static final byte CCS_PROTOCOL_TYPE = 1;

    public ChangeCipherSpecHandler(TlsContext tlsContext) {
	super(tlsContext);
	correctProtocolMessageClass = ChangeCipherSpecMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	protocolMessage.setCcsProtocolType(CCS_PROTOCOL_TYPE);
	if ((tlsContext.isRenegotiation() && tlsContext.getMyConnectionEnd() == ConnectionEnd.CLIENT)
		|| tlsContext.getRecordHandler().getRecordCipher() == null) {
	    setRecordCipher();
	}
	byte[] result = { protocolMessage.getCcsProtocolType().getValue() };
	return result;
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if ((tlsContext.isRenegotiation() && tlsContext.getMyConnectionEnd() == ConnectionEnd.SERVER)
		|| tlsContext.getRecordHandler().getRecordCipher() == null) {
	    setRecordCipher();
	}
	protocolMessage.setCcsProtocolType(message[pointer]);
	return pointer + 1;
    }

    public void setRecordCipher() {
	try {
	    TlsRecordBlockCipher tlsRecordBlockCipher = new TlsRecordBlockCipher(tlsContext);
	    tlsContext.getRecordHandler().setRecordCipher(tlsRecordBlockCipher);
	} catch (InvalidKeyException ex) {
	    throw new CryptoException(
		    "It was not possible to initialize an algorithm from "
			    + tlsContext.getSelectedCipherSuite()
			    + ". Most probably your platform does not support unlimited policy strength and you have to "
			    + "install Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files. Stupid, I know.",
		    ex);
	} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException ex) {
	    throw new CryptoException(ex);
	}
    }
}
