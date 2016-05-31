/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.util.ArrayConverter;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class FinishedMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.HMAC)
    ModifiableByteArray verifyData;

    public FinishedMessage() {
	super(HandshakeMessageType.FINISHED);
    }

    public FinishedMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.FINISHED);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByteArray getVerifyData() {
	return verifyData;
    }

    public void setVerifyData(ModifiableByteArray verifyData) {
	this.verifyData = verifyData;
    }

    public void setVerifyData(byte[] value) {
	this.verifyData = ModifiableVariableFactory.safelySetValue(this.verifyData, value);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\nFinished message:").append(super.toString()).append("\n  Verify Data: ")
		.append(ArrayConverter.bytesToHexString(verifyData.getValue()));
	return sb.toString();
    }
}
