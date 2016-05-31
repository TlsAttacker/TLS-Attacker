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
import anonymous.tlsattacker.tls.protocol.ModifiableVariableHolder;
import anonymous.tlsattacker.tls.constants.ExtensionType;
import anonymous.tlsattacker.tls.protocol.extension.ExtensionHandler;
import anonymous.tlsattacker.util.ArrayConverter;
import java.io.Serializable;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
@XmlRootElement
public abstract class ExtensionMessage extends ModifiableVariableHolder implements Serializable {

    ExtensionType extensionTypeConstant;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray extensionType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger extensionLength;

    @ModifiableVariableProperty
    ModifiableByteArray extensionBytes;

    public ModifiableByteArray getExtensionType() {
	return extensionType;
    }

    public ModifiableInteger getExtensionLength() {
	return extensionLength;
    }

    public ModifiableByteArray getExtensionBytes() {
	return extensionBytes;
    }

    public void setExtensionType(byte[] array) {
	this.extensionType = ModifiableVariableFactory.safelySetValue(extensionType, array);
    }

    public void setExtensionLength(int length) {
	this.extensionLength = ModifiableVariableFactory.safelySetValue(extensionLength, length);
    }

    public void setExtensionBytes(byte[] data) {
	this.extensionBytes = ModifiableVariableFactory.safelySetValue(extensionBytes, data);
    }

    public void setExtensionType(ModifiableByteArray extensionType) {
	this.extensionType = extensionType;
    }

    public void setExtensionLength(ModifiableInteger extensionLength) {
	this.extensionLength = extensionLength;
    }

    public void setExtensionBytes(ModifiableByteArray extensionBytes) {
	this.extensionBytes = extensionBytes;
    }

    public ExtensionType getExtensionTypeConstant() {
	return extensionTypeConstant;
    }

    public abstract ExtensionHandler getExtensionHandler();

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\n    Extension type: ").append(ArrayConverter.bytesToHexString(extensionType.getValue()))
		.append("\n    Extension length: ").append(extensionLength.getValue());
	return sb.toString();
    }
}
