/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.extension;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariable;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.tls.constants.ECPointFormat;
import anonymous.tlsattacker.tls.constants.ExtensionType;
import anonymous.tlsattacker.tls.protocol.extension.ECPointFormatExtensionHandler;
import anonymous.tlsattacker.tls.protocol.extension.ExtensionHandler;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
@XmlRootElement
public class ECPointFormatExtensionMessage extends ExtensionMessage {

    private List<ECPointFormat> pointFormatsConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger pointFormatsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray pointFormats;

    public ECPointFormatExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.EC_POINT_FORMATS;
    }

    public ModifiableByteArray getPointFormats() {
	return pointFormats;
    }

    public void setPointFormats(byte[] array) {
	this.pointFormats = ModifiableVariableFactory.safelySetValue(pointFormats, array);
    }

    public ModifiableInteger getPointFormatsLength() {
	return pointFormatsLength;
    }

    public void setPointFormatsLength(int length) {
	this.pointFormatsLength = ModifiableVariableFactory.safelySetValue(pointFormatsLength, length);
    }

    public void setPointFormatsLength(ModifiableInteger pointFormatsLength) {
	this.pointFormatsLength = pointFormatsLength;
    }

    public void setPointFormats(ModifiableByteArray pointFormats) {
	this.pointFormats = pointFormats;
    }

    @Override
    public ExtensionHandler getExtensionHandler() {
	return ECPointFormatExtensionHandler.getInstance();
    }

    public List<ECPointFormat> getPointFormatsConfig() {
	return pointFormatsConfig;
    }

    public void setPointFormatsConfig(List<ECPointFormat> pointFormatsConfig) {
	this.pointFormatsConfig = pointFormatsConfig;
    }

}
