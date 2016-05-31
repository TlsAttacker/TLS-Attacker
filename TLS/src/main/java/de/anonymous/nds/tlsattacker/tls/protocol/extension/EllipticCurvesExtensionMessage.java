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
import anonymous.tlsattacker.tls.constants.NamedCurve;
import anonymous.tlsattacker.tls.protocol.extension.EllipticCurvesExtensionHandler;
import anonymous.tlsattacker.tls.protocol.extension.ExtensionHandler;
import java.util.List;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class EllipticCurvesExtensionMessage extends ExtensionMessage {

    private List<NamedCurve> supportedCurvesConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger supportedCurvesLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray supportedCurves;

    public EllipticCurvesExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.ELLIPTIC_CURVES;
    }

    public ModifiableInteger getSupportedCurvesLength() {
	return supportedCurvesLength;
    }

    public void setSupportedCurvesLength(int length) {
	this.supportedCurvesLength = ModifiableVariableFactory.safelySetValue(supportedCurvesLength, length);
    }

    public ModifiableByteArray getSupportedCurves() {
	return supportedCurves;
    }

    public void setSupportedCurves(byte[] array) {
	supportedCurves = ModifiableVariableFactory.safelySetValue(supportedCurves, array);
    }

    public void setSupportedCurvesLength(ModifiableInteger supportedCurvesLength) {
	this.supportedCurvesLength = supportedCurvesLength;
    }

    public void setSupportedCurves(ModifiableByteArray supportedCurves) {
	this.supportedCurves = supportedCurves;
    }

    @Override
    public ExtensionHandler getExtensionHandler() {
	return EllipticCurvesExtensionHandler.getInstance();
    }

    public List<NamedCurve> getSupportedCurvesConfig() {
	return supportedCurvesConfig;
    }

    public void setSupportedCurvesConfig(List<NamedCurve> supportedCurvesConfig) {
	this.supportedCurvesConfig = supportedCurvesConfig;
    }
}
