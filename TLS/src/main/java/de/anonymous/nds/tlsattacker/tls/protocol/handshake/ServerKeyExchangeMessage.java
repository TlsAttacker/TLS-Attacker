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
import anonymous.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ServerKeyExchangeMessage extends HandshakeMessage {

    /**
     * hash algorithm
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte hashAlgorithm;
    /**
     * signature algorithm
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte signatureAlgorithm;
    /**
     * signature length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger signatureLength;
    /**
     * signature
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.SIGNATURE)
    ModifiableByteArray signature;

    public ServerKeyExchangeMessage(HandshakeMessageType handshakeMessageType) {
	super(handshakeMessageType);
    }

    public ModifiableVariable<Byte> getHashAlgorithm() {
	return hashAlgorithm;
    }

    public void setHashAlgorithm(ModifiableByte hashAlgorithm) {
	this.hashAlgorithm = hashAlgorithm;
    }

    public void setHashAlgorithm(byte algorithm) {
	this.hashAlgorithm = ModifiableVariableFactory.safelySetValue(this.hashAlgorithm, algorithm);
    }

    public ModifiableVariable<Byte> getSignatureAlgorithm() {
	return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(ModifiableByte signatureAlgorithm) {
	this.signatureAlgorithm = signatureAlgorithm;
    }

    public void setSignatureAlgorithm(byte algorithm) {
	this.signatureAlgorithm = ModifiableVariableFactory.safelySetValue(this.signatureAlgorithm, algorithm);
    }

    public ModifiableInteger getSignatureLength() {
	return signatureLength;
    }

    public void setSignatureLength(ModifiableInteger signatureLength) {
	this.signatureLength = signatureLength;
    }

    public void setSignatureLength(int length) {
	this.signatureLength = ModifiableVariableFactory.safelySetValue(this.signatureLength, length);
    }

    public ModifiableByteArray getSignature() {
	return signature;
    }

    public void setSignature(ModifiableByteArray signature) {
	this.signature = signature;
    }

    public void setSignature(byte[] signature) {
	this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
    }

}
