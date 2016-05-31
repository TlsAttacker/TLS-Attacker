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
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class CertificateVerifyMessage extends HandshakeMessage {
    /**
     * selected Signature and Hashalgorithm
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray signatureHashAlgorithm;
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

    public CertificateVerifyMessage() {
	super(HandshakeMessageType.CERTIFICATE_VERIFY);
	this.messageIssuer = ConnectionEnd.CLIENT;
    }

    public CertificateVerifyMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.CERTIFICATE_VERIFY);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByteArray getSignatureHashAlgorithm() {
	return signatureHashAlgorithm;
    }

    public void setSignatureHashAlgorithm(ModifiableByteArray signatureHashAlgorithm) {
	this.signatureHashAlgorithm = signatureHashAlgorithm;
    }

    public void setSignatureHashAlgorithm(byte[] signatureHashAlgorithm) {
	this.signatureHashAlgorithm = ModifiableVariableFactory.safelySetValue(this.signatureHashAlgorithm,
		signatureHashAlgorithm);
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
