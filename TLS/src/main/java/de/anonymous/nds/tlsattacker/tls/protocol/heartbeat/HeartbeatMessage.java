/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.heartbeat;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.ProtocolMessageHandler;
import anonymous.tlsattacker.tls.protocol.heartbeat.HeartbeatHandler;
import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.constants.HeartbeatMessageType;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.ArrayConverter;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class HeartbeatMessage extends ProtocolMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte heartbeatMessageType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger payloadLength;

    @ModifiableVariableProperty()
    ModifiableByteArray payload;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PADDING)
    ModifiableByteArray padding;

    public HeartbeatMessage() {
	this.protocolMessageType = ProtocolMessageType.HEARTBEAT;
    }

    public HeartbeatMessage(ConnectionEnd messageIssuer) {
	this();
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByte getHeartbeatMessageType() {
	return heartbeatMessageType;
    }

    public void setHeartbeatMessageType(ModifiableByte heartbeatMessageType) {
	this.heartbeatMessageType = heartbeatMessageType;
    }

    public void setHeartbeatMessageType(byte heartbeatMessageType) {
	this.heartbeatMessageType = ModifiableVariableFactory.safelySetValue(this.heartbeatMessageType,
		heartbeatMessageType);
    }

    public ModifiableInteger getPayloadLength() {
	return payloadLength;
    }

    public void setPayloadLength(ModifiableInteger payloadLength) {
	this.payloadLength = payloadLength;
    }

    public void setPayloadLength(int payloadLength) {
	this.payloadLength = ModifiableVariableFactory.safelySetValue(this.payloadLength, payloadLength);
    }

    public ModifiableByteArray getPayload() {
	return payload;
    }

    public void setPayload(ModifiableByteArray payload) {
	this.payload = payload;
    }

    public void setPayload(byte[] payload) {
	this.payload = ModifiableVariableFactory.safelySetValue(this.payload, payload);
    }

    public ModifiableByteArray getPadding() {
	return padding;
    }

    public void setPadding(ModifiableByteArray padding) {
	this.padding = padding;
    }

    public void setPadding(byte[] padding) {
	this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
	HeartbeatHandler hmh = new HeartbeatHandler(tlsContext);
	hmh.setProtocolMessage(this);
	return hmh;
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\nHeartbeat message:\n  Type: ")
		.append(HeartbeatMessageType.getHeartbeatMessageType(heartbeatMessageType.getValue()))
		.append("\n  Payload Length: ").append(payloadLength.getValue()).append("\n  Payload: ")
		.append(ArrayConverter.bytesToHexString(payload.getValue())).append("\n  Padding: ")
		.append(ArrayConverter.bytesToHexString(padding.getValue()));
	return sb.toString();
    }

    @Override
    public String toCompactString() {
	return "Heartbeat";
    }

}
