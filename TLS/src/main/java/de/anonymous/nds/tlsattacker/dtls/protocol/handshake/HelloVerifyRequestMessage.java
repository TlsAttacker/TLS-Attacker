/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.dtls.protocol.handshake;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.protocol.handshake.HandshakeMessage;

/**
 * @author anonymous Pfützenreuter <anonymous.Pfuetzenreuter@anonymous>
 */
public class HelloVerifyRequestMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray protocolVersion;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableByte cookieLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COOKIE)
    ModifiableByteArray cookie;

    public HelloVerifyRequestMessage() {
	super(HandshakeMessageType.HELLO_VERIFY_REQUEST);
	protocolVersion = ModifiableVariableFactory.safelySetValue(protocolVersion, ProtocolVersion.DTLS12.getValue());
	cookieLength = ModifiableVariableFactory.safelySetValue(cookieLength, (byte) 0);
	cookie = ModifiableVariableFactory.safelySetValue(cookie, new byte[0]);
    }

    public HelloVerifyRequestMessage(ConnectionEnd messageIssuer) {
	this();
	this.messageIssuer = messageIssuer;
    }

    public HelloVerifyRequestMessage(HandshakeMessageType handshakeMessageType) {
	super(handshakeMessageType);
    }

    public ModifiableByteArray getProtocolVersion() {
	return protocolVersion;
    }

    public ModifiableByteArray getCookie() {
	return cookie;
    }

    public ModifiableByte getCookieLength() {
	return cookieLength;
    }

    public void setProtocolVersion(byte[] protocolVersion) {
	this.protocolVersion = ModifiableVariableFactory.safelySetValue(this.protocolVersion, protocolVersion);
    }

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
	this.protocolVersion = protocolVersion;
    }

    public void setCookie(byte[] cookie) {
	this.cookie = ModifiableVariableFactory.safelySetValue(this.cookie, cookie);
    }

    public void setCookie(ModifiableByteArray cookie) {
	this.cookie = cookie;
    }

    public void setCookieLength(byte cookieLength) {
	this.cookieLength = ModifiableVariableFactory.safelySetValue(this.cookieLength, cookieLength);
    }

    public void setCookieLength(ModifiableByte cookieLength) {
	this.cookieLength = cookieLength;
    }
}
