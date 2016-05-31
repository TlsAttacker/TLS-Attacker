/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.extension;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.tls.constants.ExtensionType;
import anonymous.tlsattacker.tls.protocol.extension.ExtensionHandler;
import anonymous.tlsattacker.tls.protocol.extension.SignatureAndHashAlgorithmsExtensionHandler;
import anonymous.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import java.util.List;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class SignatureAndHashAlgorithmsExtensionMessage extends ExtensionMessage {

    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmsConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger signatureAndHashAlgorithmsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray signatureAndHashAlgorithms;

    public SignatureAndHashAlgorithmsExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS;
    }

    public ModifiableInteger getSignatureAndHashAlgorithmsLength() {
	return signatureAndHashAlgorithmsLength;
    }

    public void setSignatureAndHashAlgorithmsLength(int length) {
	this.signatureAndHashAlgorithmsLength = ModifiableVariableFactory.safelySetValue(
		this.signatureAndHashAlgorithmsLength, length);
    }

    public ModifiableByteArray getSignatureAndHashAlgorithms() {
	return signatureAndHashAlgorithms;
    }

    public void setSignatureAndHashAlgorithms(byte[] array) {
	this.signatureAndHashAlgorithms = ModifiableVariableFactory.safelySetValue(this.signatureAndHashAlgorithms,
		array);
    }

    public void setSignatureAndHashAlgorithmsLength(ModifiableInteger signatureAndHashAlgorithmsLength) {
	this.signatureAndHashAlgorithmsLength = signatureAndHashAlgorithmsLength;
    }

    public void setSignatureAndHashAlgorithms(ModifiableByteArray signatureAndHashAlgorithms) {
	this.signatureAndHashAlgorithms = signatureAndHashAlgorithms;
    }

    @Override
    public ExtensionHandler getExtensionHandler() {
	return SignatureAndHashAlgorithmsExtensionHandler.getInstance();
    }

    public List<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithmsConfig() {
	return signatureAndHashAlgorithmsConfig;
    }

    public void setSignatureAndHashAlgorithmsConfig(List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmsConfig) {
	this.signatureAndHashAlgorithmsConfig = signatureAndHashAlgorithmsConfig;
    }
}
