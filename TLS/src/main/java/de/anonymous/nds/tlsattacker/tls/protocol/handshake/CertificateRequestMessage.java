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
import anonymous.tlsattacker.tls.constants.ClientCertificateType;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.constants.HashAlgorithm;
import anonymous.tlsattacker.tls.constants.SignatureAlgorithm;

/**
 * import java.util.LinkedList;
 * import java.util.List;
 * import javax.xml.bind.annotation.XmlAccessType;
 * import javax.xml.bind.annotation.XmlAccessorType;
 * import javax.xml.bind.annotation.XmlElement;
 * import javax.xml.bind.annotation.XmlElementWrapper;
 * import javax.xml.bind.annotation.XmlElements;
 * import javax.xml.bind.annotation.XmlRootElement;
 */

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */

/**
 * @XmlRootElement
 * @XmlAccessorType(XmlAccessType.FIELD)
 */
public class CertificateRequestMessage extends HandshakeMessage {

    /**
     * List of supported Client Certificate Types
     * 
     * @XmlElementWrapper
     * @XmlElements(value = { @XmlElement(type = ClientCertificateType.class,
     *                    name = "ClientCertificateTypes") }) private
     *                    List<ClientCertificateType>
     *                    supportedClientCertificateTypes = new LinkedList<>();
     */

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    ModifiableInteger clientCertificateTypesCount;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray clientCertificateTypes;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger signatureHashAlgorithmsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray signatureHashAlgorithms;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger distinguishedNamesLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray distinguishedNames;

    public CertificateRequestMessage() {
	super(HandshakeMessageType.CERTIFICATE_REQUEST);
	this.messageIssuer = ConnectionEnd.SERVER;
    }

    public CertificateRequestMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.CERTIFICATE_REQUEST);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableInteger getClientCertificateTypesCount() {
	return clientCertificateTypesCount;
    }

    public void setClientCertificateTypesCount(ModifiableInteger clientCertificateTypesCount) {
	this.clientCertificateTypesCount = clientCertificateTypesCount;
    }

    public void setClientCertificateTypesCount(int clientCertificateTypesCount) {
	this.clientCertificateTypesCount = ModifiableVariableFactory.safelySetValue(this.clientCertificateTypesCount,
		clientCertificateTypesCount);
    }

    public ModifiableByteArray getClientCertificateTypes() {
	return clientCertificateTypes;
    }

    public void setClientCertificateTypes(ModifiableByteArray clientCertificateTypes) {
	this.clientCertificateTypes = clientCertificateTypes;
    }

    public void setClientCertificateTypes(byte[] clientCertificateTypes) {
	this.clientCertificateTypes = ModifiableVariableFactory.safelySetValue(this.clientCertificateTypes,
		clientCertificateTypes);
    }

    public ModifiableInteger getSignatureHashAlgorithmsLength() {
	return signatureHashAlgorithmsLength;
    }

    public void setSignatureHashAlgorithmsLength(ModifiableInteger signatureHashAlgorithmsLength) {
	this.signatureHashAlgorithmsLength = signatureHashAlgorithmsLength;
    }

    public void setSignatureHashAlgorithmsLength(int signatureHashAlgorithmsLength) {
	this.signatureHashAlgorithmsLength = ModifiableVariableFactory.safelySetValue(
		this.signatureHashAlgorithmsLength, signatureHashAlgorithmsLength);
    }

    public ModifiableByteArray getSignatureHashAlgorithms() {
	return signatureHashAlgorithms;
    }

    public void setSignatureHashAlgorithms(ModifiableByteArray signatureHashAlgorithms) {
	this.signatureHashAlgorithms = signatureHashAlgorithms;
    }

    public void setSignatureHashAlgorithms(byte[] signatureHashAlgorithms) {
	this.signatureHashAlgorithms = ModifiableVariableFactory.safelySetValue(this.signatureHashAlgorithms,
		signatureHashAlgorithms);
    }

    public ModifiableInteger getDistinguishedNamesLength() {
	return distinguishedNamesLength;
    }

    public void setDistinguishedNamesLength(ModifiableInteger distinguishedNamesLength) {
	this.distinguishedNamesLength = distinguishedNamesLength;
    }

    public void setDistinguishedNamesLength(int distinguishedNamesLength) {
	this.distinguishedNamesLength = ModifiableVariableFactory.safelySetValue(this.distinguishedNamesLength,
		distinguishedNamesLength);
    }

    public ModifiableByteArray getDistinguishedNames() {
	return distinguishedNames;
    }

    public void setDistinguishedNames(ModifiableByteArray distinguishedNames) {
	this.distinguishedNames = distinguishedNames;
    }

    public void setDistinguishedNames(byte[] distinguishedNames) {
	this.distinguishedNames = ModifiableVariableFactory.safelySetValue(this.distinguishedNames, distinguishedNames);
    }

    /**
     * public void
     * setSupportedClientCertificateTypes(List<ClientCertificateType>
     * supportedClientCertificateTypes) { this.supportedClientCertificateTypes =
     * supportedClientCertificateTypes; }
     */

    /**
     * public List<ClientCertificateType> getSupportedClientCertificateTypes() {
     * return supportedClientCertificateTypes; }
     */

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder(super.toString());
	sb.append("\n  Certificate Types Count: ").append(clientCertificateTypesCount.getValue());
	sb.append("\n  Certificate Types: ");
	for (int i = 0; i < clientCertificateTypesCount.getValue(); i++) {
	    sb.append(ClientCertificateType.getClientCertificateType(clientCertificateTypes.getValue()[i]))
		    .append(", ");
	}
	sb.append("\n  Signature Hash Algorithms Length: ").append(signatureHashAlgorithmsLength.getValue());
	sb.append("\n  Signature Hash Algorithms: ");
	for (int i = 0; i < signatureHashAlgorithmsLength.getValue(); i = i + 2) {
	    sb.append(HashAlgorithm.getHashAlgorithm(signatureHashAlgorithms.getValue()[i])).append("-");
	    sb.append(SignatureAlgorithm.getSignatureAlgorithm(signatureHashAlgorithms.getValue()[i + 1])).append(", ");
	}
	sb.append("\n  Distinguished Names Length: ").append(distinguishedNamesLength.getValue());
	// sb.append("\n  Distinguished Names: ").append(ArrayConverter.bytesToHexString(distinguishedNames.getValue()));
	return sb.toString();
    }

}
