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
import anonymous.tlsattacker.tls.constants.ExtensionType;
import anonymous.tlsattacker.tls.constants.MaxFragmentLength;
import anonymous.tlsattacker.tls.protocol.extension.ExtensionHandler;
import anonymous.tlsattacker.tls.protocol.extension.MaxFragmentLengthExtensionHandler;

/**
 * Maximum Fragment Length Extension described in rfc3546
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class MaxFragmentLengthExtensionMessage extends ExtensionMessage {

    private MaxFragmentLength maxFragmentLengthConfig;

    /**
     * Maximum fragment length value described in rfc3546
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray maxFragmentLength;

    public MaxFragmentLengthExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.MAX_FRAGMENT_LENGTH;
    }

    public MaxFragmentLength getMaxFragmentLengthConfig() {
	return maxFragmentLengthConfig;
    }

    public void setMaxFragmentLengthConfig(MaxFragmentLength maxFragmentLengthConfig) {
	this.maxFragmentLengthConfig = maxFragmentLengthConfig;
    }

    public ModifiableByteArray getMaxFragmentLength() {
	return maxFragmentLength;
    }

    public void setMaxFragmentLength(ModifiableByteArray maxFragmentLength) {
	this.maxFragmentLength = maxFragmentLength;
    }

    public void setMaxFragmentLength(byte[] maxFragmentLength) {
	this.maxFragmentLength = ModifiableVariableFactory.safelySetValue(this.maxFragmentLength, maxFragmentLength);
    }

    @Override
    public ExtensionHandler getExtensionHandler() {
	return MaxFragmentLengthExtensionHandler.getInstance();
    }

}
