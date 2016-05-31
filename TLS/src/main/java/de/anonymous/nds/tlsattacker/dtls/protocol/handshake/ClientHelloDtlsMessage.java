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
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import anonymous.tlsattacker.util.ArrayConverter;

/**
 * @author anonymous Pfützenreuter <anonymous.Pfuetzenreuter@anonymous>
 */
public class ClientHelloDtlsMessage extends ClientHelloMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COOKIE)
    ModifiableByteArray cookie;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableByte cookieLength;

    public ClientHelloDtlsMessage() {
	cookie = ModifiableVariableFactory.safelySetValue(cookie, new byte[0]);
	cookieLength = ModifiableVariableFactory.safelySetValue(cookieLength, (byte) 0);
	this.messageIssuer = ConnectionEnd.CLIENT;
    }

    public ClientHelloDtlsMessage(ConnectionEnd messageIssuer) {
	this();
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByteArray getCookie() {
	return cookie;
    }

    public ModifiableByte getCookieLength() {
	return cookieLength;
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

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append(super.toString()).append("\n DTLS cookie length: ").append(cookieLength.getValue())
		.append("\n DTLS cookie: ").append(ArrayConverter.bytesToHexString(cookie.getValue()));
	return sb.toString();
    }
}
