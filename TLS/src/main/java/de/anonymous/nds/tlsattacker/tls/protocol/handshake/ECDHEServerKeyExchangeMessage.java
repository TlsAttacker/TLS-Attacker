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
import anonymous.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.constants.EllipticCurveType;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.constants.HashAlgorithm;
import anonymous.tlsattacker.tls.constants.NamedCurve;
import anonymous.tlsattacker.tls.constants.SignatureAlgorithm;
import anonymous.tlsattacker.util.ArrayConverter;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ECDHEServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte curveType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray namedCurve;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger publicKeyLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableByteArray publicKey;

    public ECDHEServerKeyExchangeMessage() {
	super(HandshakeMessageType.SERVER_KEY_EXCHANGE);
	this.messageIssuer = ConnectionEnd.SERVER;
    }

    public ECDHEServerKeyExchangeMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.SERVER_KEY_EXCHANGE);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByte getCurveType() {
	return curveType;
    }

    public void setCurveType(ModifiableByte curveType) {
	this.curveType = curveType;
    }

    public void setCurveType(byte curveType) {
	this.curveType = ModifiableVariableFactory.safelySetValue(this.curveType, curveType);
    }

    public ModifiableByteArray getNamedCurve() {
	return namedCurve;
    }

    public void setNamedCurve(ModifiableByteArray namedCurve) {
	this.namedCurve = namedCurve;
    }

    public void setNamedCurve(byte[] namedCurve) {
	this.namedCurve = ModifiableVariableFactory.safelySetValue(this.namedCurve, namedCurve);
    }

    public ModifiableInteger getPublicKeyLength() {
	return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableInteger publicKeyLength) {
	this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(int length) {
	this.publicKeyLength = ModifiableVariableFactory.safelySetValue(this.publicKeyLength, length);
    }

    public ModifiableByteArray getPublicKey() {
	return publicKey;
    }

    public void setPublicKey(ModifiableByteArray publicKey) {
	this.publicKey = publicKey;
    }

    public void setPublicKey(byte[] pubKey) {
	this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, pubKey);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append(super.toString()).append("\n  Curve Type: ")
		.append(EllipticCurveType.getCurveType(this.curveType.getValue())).append("\n  Named Curve: ")
		.append(NamedCurve.getNamedCurve(this.namedCurve.getValue())).append("\n  Public Key: ")
		.append(ArrayConverter.bytesToHexString(this.publicKey.getValue())).append("\n  Signature Algorithm: ");
	// signature and hash algorithms are provided only while working with
	// (D)TLS 1.2
	if (this.getHashAlgorithm() != null) {
	    sb.append(HashAlgorithm.getHashAlgorithm(this.hashAlgorithm.getValue())).append(" ");
	}
	if (this.getSignatureAlgorithm() != null) {
	    sb.append(SignatureAlgorithm.getSignatureAlgorithm(this.signatureAlgorithm.getValue()));
	}
	sb.append("\n  Signature: ").append(ArrayConverter.bytesToHexString(this.signature.getValue()));

	return sb.toString();
    }
}
