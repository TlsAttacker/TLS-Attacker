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
import anonymous.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import anonymous.tlsattacker.tls.constants.ExtensionType;
import anonymous.tlsattacker.tls.constants.NameType;
import anonymous.tlsattacker.tls.protocol.extension.ExtensionHandler;
import anonymous.tlsattacker.tls.protocol.extension.ServerNameIndicationExtensionHandler;

/**
 * Describes Server Name Indication extension from
 * http://tools.ietf.org/html/rfc6066
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ServerNameIndicationExtensionMessage extends ExtensionMessage {

    private NameType nameTypeConfig;

    private String serverNameConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger serverNameListLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte serverNameType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger serverNameLength;

    @ModifiableVariableProperty
    ModifiableByteArray serverName;

    public ServerNameIndicationExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.SERVER_NAME_INDICATION;
    }

    public NameType getNameTypeConfig() {
	return nameTypeConfig;
    }

    public void setNameTypeConfig(NameType nameTypeConfig) {
	this.nameTypeConfig = nameTypeConfig;
    }

    public ModifiableInteger getServerNameListLength() {
	return serverNameListLength;
    }

    public void setServerNameListLength(ModifiableInteger serverNameListLength) {
	this.serverNameListLength = serverNameListLength;
    }

    public void setServerNameListLength(int length) {
	this.serverNameListLength = ModifiableVariableFactory.safelySetValue(serverNameListLength, length);
    }

    public ModifiableByte getServerNameType() {
	return serverNameType;
    }

    public void setServerNameType(ModifiableByte serverNameType) {
	this.serverNameType = serverNameType;
    }

    public void setServerNameType(byte serverNameType) {
	this.serverNameType = ModifiableVariableFactory.safelySetValue(this.serverNameType, serverNameType);
    }

    public ModifiableInteger getServerNameLength() {
	return serverNameLength;
    }

    public void setServerNameLength(ModifiableInteger serverNameLength) {
	this.serverNameLength = serverNameLength;
    }

    public void setServerNameLength(int serverNameLength) {
	this.serverNameLength = ModifiableVariableFactory.safelySetValue(this.serverNameLength, serverNameLength);
    }

    public ModifiableByteArray getServerName() {
	return serverName;
    }

    public void setServerName(ModifiableByteArray serverName) {
	this.serverName = serverName;
    }

    public void setServerName(byte[] serverName) {
	this.serverName = ModifiableVariableFactory.safelySetValue(this.serverName, serverName);
    }

    public String getServerNameConfig() {
	return serverNameConfig;
    }

    public void setServerNameConfig(String serverNameConfig) {
	this.serverNameConfig = serverNameConfig;
    }

    @Override
    public ExtensionHandler getExtensionHandler() {
	return ServerNameIndicationExtensionHandler.getInstance();
    }

}
