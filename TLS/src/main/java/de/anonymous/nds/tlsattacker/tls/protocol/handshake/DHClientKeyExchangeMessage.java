/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import java.math.BigInteger;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class DHClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    /**
     * DH modulus
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableBigInteger p;
    /**
     * DH generator
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableBigInteger g;
    /**
     * server's public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableBigInteger y;
    /**
     * client's private key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PRIVATE_KEY)
    ModifiableBigInteger x;
    /**
     * Length of the serialized public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger serializedPublicKeyLength;
    /**
     * serialized public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableByteArray serializedPublicKey;

    public DHClientKeyExchangeMessage() {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = ConnectionEnd.CLIENT;
    }

    public DHClientKeyExchangeMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableBigInteger getP() {
	return p;
    }

    public void setP(ModifiableBigInteger p) {
	this.p = p;
    }

    public void setP(BigInteger p) {
	this.p = ModifiableVariableFactory.safelySetValue(this.p, p);
    }

    public ModifiableBigInteger getG() {
	return g;
    }

    public void setG(ModifiableBigInteger g) {
	this.g = g;
    }

    public void setG(BigInteger g) {
	this.g = ModifiableVariableFactory.safelySetValue(this.g, g);
    }

    public ModifiableBigInteger getY() {
	return y;
    }

    public void setY(ModifiableBigInteger y) {
	this.y = y;
    }

    public void setY(BigInteger y) {
	this.y = ModifiableVariableFactory.safelySetValue(this.y, y);
    }

    public ModifiableBigInteger getX() {
	return x;
    }

    public void setX(ModifiableBigInteger x) {
	this.x = x;
    }

    public void setX(BigInteger x) {
	this.x = ModifiableVariableFactory.safelySetValue(this.x, x);
    }

    public ModifiableInteger getSerializedPublicKeyLength() {
	return serializedPublicKeyLength;
    }

    public void setSerializedPublicKeyLength(ModifiableInteger serializedPublicKeyLength) {
	this.serializedPublicKeyLength = serializedPublicKeyLength;
    }

    public void setSerializedPublicKeyLength(Integer publicKeyLength) {
	this.serializedPublicKeyLength = ModifiableVariableFactory.safelySetValue(this.serializedPublicKeyLength,
		publicKeyLength);
    }

    public ModifiableByteArray getSerializedPublicKey() {
	return serializedPublicKey;
    }

    public void setSerializedPublicKey(ModifiableByteArray serializedPublicKey) {
	this.serializedPublicKey = serializedPublicKey;
    }

    public void setSerializedPublicKey(byte[] serializedPublicKey) {
	this.serializedPublicKey = ModifiableVariableFactory.safelySetValue(this.serializedPublicKey,
		serializedPublicKey);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder(super.toString());
	sb.append("\n  Y (client's public key): ").append(y.getValue().toString(16));
	return sb.toString();
    }
}
