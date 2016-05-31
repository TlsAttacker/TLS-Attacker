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
import anonymous.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.extension.ExtensionMessage;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.constants.CompressionMethod;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.util.ArrayConverter;
import java.util.Date;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ServerHelloMessage extends HelloMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray selectedCipherSuite;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte selectedCompressionMethod;

    public ServerHelloMessage() {
	super(HandshakeMessageType.SERVER_HELLO);
	this.messageIssuer = ConnectionEnd.SERVER;
    }

    public ServerHelloMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.SERVER_HELLO);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByteArray getSelectedCipherSuite() {
	return selectedCipherSuite;
    }

    public void setSelectedCipherSuite(ModifiableByteArray selectedCipherSuite) {
	this.selectedCipherSuite = selectedCipherSuite;
    }

    public void setSelectedCipherSuite(byte[] value) {
	this.selectedCipherSuite = ModifiableVariableFactory.safelySetValue(this.selectedCipherSuite, value);
    }

    public ModifiableByte getSelectedCompressionMethod() {
	return selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(ModifiableByte selectedCompressionMethod) {
	this.selectedCompressionMethod = selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(byte value) {
	this.selectedCompressionMethod = ModifiableVariableFactory
		.safelySetValue(this.selectedCompressionMethod, value);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append(super.toString()).append("\n  Protocol Version: ")
		.append(ProtocolVersion.getProtocolVersion(protocolVersion.getValue()))
		.append("\n  Server Unix Time: ")
		.append(new Date(ArrayConverter.bytesToLong(this.unixTime.getValue()) * 1000))
		.append("\n  Server Random: ").append(ArrayConverter.bytesToHexString(random.getValue()))
		.append("\n  Session ID: ").append(ArrayConverter.bytesToHexString(sessionId.getValue()))
		.append("\n  Selected Cipher Suite: ")
		.append(CipherSuite.getCipherSuite(selectedCipherSuite.getValue()))
		.append("\n  Selected Compression Method: ")
		.append(CompressionMethod.getCompressionMethod(selectedCompressionMethod.getValue()))
		.append("\n  Extensions: ");
	for (ExtensionMessage e : extensions) {
	    sb.append(e.toString());
	}
	return sb.toString();
    }
}
