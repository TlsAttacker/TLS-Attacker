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
import anonymous.tlsattacker.tls.constants.ExtensionType;
import anonymous.tlsattacker.tls.constants.HeartbeatMode;
import anonymous.tlsattacker.tls.protocol.extension.ExtensionHandler;
import anonymous.tlsattacker.tls.protocol.extension.HeartbeatExtensionHandler;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class HeartbeatExtensionMessage extends ExtensionMessage {

    private HeartbeatMode heartbeatModeConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray heartbeatMode;

    public HeartbeatExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.HEARTBEAT;
    }

    public ModifiableByteArray getHeartbeatMode() {
	return heartbeatMode;
    }

    public void setHeartbeatMode(ModifiableByteArray heartbeatMode) {
	this.heartbeatMode = heartbeatMode;
    }

    public void setHeartbeatMode(byte[] heartbeatMode) {
	this.heartbeatMode = ModifiableVariableFactory.safelySetValue(this.heartbeatMode, heartbeatMode);
    }

    public HeartbeatMode getHeartbeatModeConfig() {
	return heartbeatModeConfig;
    }

    public void setHeartbeatModeConfig(HeartbeatMode heartbeatModeConfig) {
	this.heartbeatModeConfig = heartbeatModeConfig;
    }

    @Override
    public ExtensionHandler getExtensionHandler() {
	return HeartbeatExtensionHandler.getInstance();
    }

}
