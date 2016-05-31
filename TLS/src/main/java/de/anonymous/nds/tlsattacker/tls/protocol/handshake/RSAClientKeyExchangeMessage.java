/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariable;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class RSAClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger encryptedPremasterSecretLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CIPHERTEXT)
    ModifiableByteArray encryptedPremasterSecret;

    @ModifiableVariableProperty(format = ModifiableVariableProperty.Format.PKCS1, type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    ModifiableByteArray plainPaddedPremasterSecret;

    public RSAClientKeyExchangeMessage() {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = ConnectionEnd.CLIENT;
    }

    public RSAClientKeyExchangeMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableInteger getEncryptedPremasterSecretLength() {
	return encryptedPremasterSecretLength;
    }

    public void setEncryptedPremasterSecretLength(ModifiableInteger encryptedPremasterSecretLength) {
	this.encryptedPremasterSecretLength = encryptedPremasterSecretLength;
    }

    public void setEncryptedPremasterSecretLength(int length) {
	this.encryptedPremasterSecretLength = ModifiableVariableFactory.safelySetValue(
		this.encryptedPremasterSecretLength, length);
    }

    public ModifiableByteArray getEncryptedPremasterSecret() {
	return encryptedPremasterSecret;
    }

    public void setEncryptedPremasterSecret(ModifiableByteArray encryptedPremasterSecret) {
	this.encryptedPremasterSecret = encryptedPremasterSecret;
    }

    public void setEncryptedPremasterSecret(byte[] value) {
	this.encryptedPremasterSecret = ModifiableVariableFactory.safelySetValue(this.encryptedPremasterSecret, value);
    }

    public ModifiableByteArray getPlainPaddedPremasterSecret() {
	return plainPaddedPremasterSecret;
    }

    public void setPlainPaddedPremasterSecret(ModifiableByteArray plainPaddedPremasterSecret) {
	this.plainPaddedPremasterSecret = plainPaddedPremasterSecret;
    }

    public void setPlainPaddedPremasterSecret(byte[] value) {
	this.plainPaddedPremasterSecret = ModifiableVariableFactory.safelySetValue(this.plainPaddedPremasterSecret,
		value);
    }

    public void setMasterSecret(ModifiableByteArray masterSecret) {
	this.masterSecret = masterSecret;
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\nClient Key Exchange message:");
	return sb.toString();
    }
}
