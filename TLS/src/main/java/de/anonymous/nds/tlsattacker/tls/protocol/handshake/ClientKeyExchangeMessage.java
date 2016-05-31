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
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ClientKeyExchangeMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    ModifiableByteArray masterSecret;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    ModifiableByteArray premasterSecret;

    public ClientKeyExchangeMessage(HandshakeMessageType handshakeMessageType) {
	super(handshakeMessageType);
    }

    public ModifiableByteArray getMasterSecret() {
	return masterSecret;
    }

    public void setMasterSecret(ModifiableByteArray masterSecret) {
	this.masterSecret = masterSecret;
    }

    public void setMasterSecret(byte[] value) {
	this.masterSecret = ModifiableVariableFactory.safelySetValue(this.masterSecret, value);
    }

    public ModifiableByteArray getPremasterSecret() {
	return premasterSecret;
    }

    public void setPremasterSecret(ModifiableByteArray premasterSecret) {
	this.premasterSecret = premasterSecret;
    }

    public void setPremasterSecret(byte[] premasterSecret) {
	this.premasterSecret = ModifiableVariableFactory.safelySetValue(this.premasterSecret, premasterSecret);
    }

}
