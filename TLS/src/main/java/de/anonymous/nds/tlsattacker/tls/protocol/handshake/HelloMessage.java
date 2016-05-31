/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.handshake;

import anonymous.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariable;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.tls.protocol.ModifiableVariableHolder;
import anonymous.tlsattacker.tls.constants.ExtensionType;
import anonymous.tlsattacker.tls.protocol.extension.ECPointFormatExtensionMessage;
import anonymous.tlsattacker.tls.protocol.extension.EllipticCurvesExtensionMessage;
import anonymous.tlsattacker.tls.protocol.extension.ExtensionMessage;
import anonymous.tlsattacker.tls.protocol.extension.HeartbeatExtensionMessage;
import anonymous.tlsattacker.tls.protocol.extension.MaxFragmentLengthExtensionMessage;
import anonymous.tlsattacker.tls.protocol.extension.ServerNameIndicationExtensionMessage;
import anonymous.tlsattacker.tls.protocol.extension.SignatureAndHashAlgorithmsExtensionMessage;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
abstract class HelloMessage extends HandshakeMessage {

    /**
     * protocol version in the client and server hello
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray protocolVersion;
    /**
     * unix time
     */
    @ModifiableVariableProperty
    ModifiableByteArray unixTime;
    /**
     * random
     */
    @ModifiableVariableProperty
    ModifiableByteArray random;
    /**
     * length of the session id length field indicating the session id length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger sessionIdLength;
    /**
     * session id
     */
    @ModifiableVariableProperty
    ModifiableByteArray sessionId;
    /**
     * List of extensions
     */
    @HoldsModifiableVariable
    List<ExtensionMessage> extensions = new LinkedList<>();

    public HelloMessage(HandshakeMessageType handshakeMessageType) {
	super(handshakeMessageType);
    }

    public ModifiableByteArray getRandom() {
	return random;
    }

    public ModifiableByteArray getSessionId() {
	return sessionId;
    }

    public ModifiableByteArray getUnixTime() {
	return unixTime;
    }

    public ModifiableByteArray getProtocolVersion() {
	return protocolVersion;
    }

    public ModifiableInteger getSessionIdLength() {
	return sessionIdLength;
    }

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
	this.protocolVersion = protocolVersion;
    }

    public void setUnixTime(ModifiableByteArray unixTime) {
	this.unixTime = unixTime;
    }

    public void setRandom(ModifiableByteArray random) {
	this.random = random;
    }

    public void setSessionIdLength(ModifiableInteger sessionIdLength) {
	this.sessionIdLength = sessionIdLength;
    }

    public void setSessionId(ModifiableByteArray sessionId) {
	this.sessionId = sessionId;
    }

    public void setRandom(byte[] random) {
	this.random = ModifiableVariableFactory.safelySetValue(this.random, random);
    }

    public void setSessionId(byte[] sessionId) {
	this.sessionId = ModifiableVariableFactory.safelySetValue(this.sessionId, sessionId);
    }

    public void setUnixTime(byte[] unixTime) {
	this.unixTime = ModifiableVariableFactory.safelySetValue(this.unixTime, unixTime);
    }

    public void setSessionIdLength(int sessionIdLength) {
	this.sessionIdLength = ModifiableVariableFactory.safelySetValue(this.sessionIdLength, sessionIdLength);
    }

    public void setProtocolVersion(byte[] array) {
	this.protocolVersion = ModifiableVariableFactory.safelySetValue(this.protocolVersion, array);
    }

    @XmlElementWrapper
    @XmlElements(value = {
	    @XmlElement(type = ECPointFormatExtensionMessage.class, name = "ECPointFormat"),
	    @XmlElement(type = EllipticCurvesExtensionMessage.class, name = "EllipticCurves"),
	    @XmlElement(type = HeartbeatExtensionMessage.class, name = "HeartbeatExtension"),
	    @XmlElement(type = MaxFragmentLengthExtensionMessage.class, name = "MaxFragmentLengthExtension"),
	    @XmlElement(type = ServerNameIndicationExtensionMessage.class, name = "ServerNameIndicationExtension"),
	    @XmlElement(type = SignatureAndHashAlgorithmsExtensionMessage.class, name = "SignatureAndHashAlgorithmsExtension") })
    public List<ExtensionMessage> getExtensions() {
	return extensions;
    }

    public void setExtensions(List<ExtensionMessage> extensions) {
	this.extensions = extensions;
    }

    public void addExtension(ExtensionMessage extension) {
	this.extensions.add(extension);
    }

    public boolean containsExtension(ExtensionType extensionType) {
	for (ExtensionMessage e : extensions) {
	    if (e.getExtensionTypeConstant() == extensionType) {
		return true;
	    }
	}
	return false;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
	List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
	if (extensions != null) {
	    for (ExtensionMessage em : extensions) {
		holders.add(em);
	    }
	}
	return holders;
    }
}
