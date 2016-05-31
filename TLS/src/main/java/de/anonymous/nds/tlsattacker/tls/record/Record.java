/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.record;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import anonymous.tlsattacker.tls.protocol.ModifiableVariableHolder;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class Record extends ModifiableVariableHolder {

    /**
     * maximum length configuration for this record
     */
    private Integer maxRecordLengthConfig;

    /**
     * total length of the protocol message (handshake, alert..) included in the
     * record layer
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger length;

    /**
     * Content type
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte contentType;

    /**
     * Record Layer Protocol Version
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray protocolVersion;

    /**
     * protocol message bytes transported in the record
     */
    @ModifiableVariableProperty
    ModifiableByteArray protocolMessageBytes;

    /**
     * MAC (message authentication code) for the record (if needed)
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.HMAC)
    ModifiableByteArray mac;

    /**
     * Padding
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PADDING)
    ModifiableByteArray padding;

    /**
     * Padding length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger paddingLength;

    /**
     * Plain record bytes (MACed and padded data)
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PADDING)
    ModifiableByteArray plainRecordBytes;

    /**
     * encrypted protocol message bytes (if encryption activated)
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CIPHERTEXT)
    ModifiableByteArray encryptedProtocolMessageBytes;

    /**
     * It is possible to define a sleep [in milliseconds] after the protocol
     * message was sent.
     */
    private int sleepAfterMessageSent;

    public ModifiableInteger getLength() {
	return length;
    }

    public ModifiableByte getContentType() {
	return contentType;
    }

    public ModifiableByteArray getProtocolVersion() {
	return protocolVersion;
    }

    public ModifiableByteArray getMac() {
	return mac;
    }

    public ModifiableByteArray getPadding() {
	return padding;
    }

    public ModifiableByteArray getProtocolMessageBytes() {
	return protocolMessageBytes;
    }

    public void setProtocolMessageBytes(ModifiableByteArray protocolMessageBytes) {
	this.protocolMessageBytes = protocolMessageBytes;
    }

    public void setLength(ModifiableInteger length) {
	this.length = length;
    }

    public void setContentType(ModifiableByte contentType) {
	this.contentType = contentType;
    }

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
	this.protocolVersion = protocolVersion;
    }

    public void setLength(int length) {
	this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public void setContentType(byte contentType) {
	this.contentType = ModifiableVariableFactory.safelySetValue(this.contentType, contentType);
    }

    public void setProtocolVersion(byte[] array) {
	this.protocolVersion = ModifiableVariableFactory.safelySetValue(this.protocolVersion, array);
    }

    public void setMac(byte[] mac) {
	this.mac = ModifiableVariableFactory.safelySetValue(this.mac, mac);
    }

    public void setPadding(byte[] padding) {
	this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }

    public void setPadding(ModifiableByteArray padding) {
	this.padding = padding;
    }

    public void setMac(ModifiableByteArray mac) {
	this.mac = mac;
    }

    public void setProtocolMessageBytes(byte[] bytes) {
	this.protocolMessageBytes = ModifiableVariableFactory.safelySetValue(this.protocolMessageBytes, bytes);
    }

    public ModifiableInteger getPaddingLength() {
	return paddingLength;
    }

    public void setPaddingLength(ModifiableInteger paddingLength) {
	this.paddingLength = paddingLength;
    }

    public void setPaddingLength(int paddingLength) {
	this.paddingLength = ModifiableVariableFactory.safelySetValue(this.paddingLength, paddingLength);
    }

    public ModifiableByteArray getPlainRecordBytes() {
	return plainRecordBytes;
    }

    public void setPlainRecordBytes(ModifiableByteArray plainRecordBytes) {
	this.plainRecordBytes = plainRecordBytes;
    }

    public void setPlainRecordBytes(byte[] value) {
	this.plainRecordBytes = ModifiableVariableFactory.safelySetValue(this.plainRecordBytes, value);
    }

    public ModifiableByteArray getEncryptedProtocolMessageBytes() {
	return encryptedProtocolMessageBytes;
    }

    public void setEncryptedProtocolMessageBytes(ModifiableByteArray encryptedProtocolMessageBytes) {
	this.encryptedProtocolMessageBytes = encryptedProtocolMessageBytes;
    }

    public void setEncryptedProtocolMessageBytes(byte[] value) {
	this.encryptedProtocolMessageBytes = ModifiableVariableFactory.safelySetValue(
		this.encryptedProtocolMessageBytes, value);
    }

    public Integer getMaxRecordLengthConfig() {
	return maxRecordLengthConfig;
    }

    public void setMaxRecordLengthConfig(Integer maxRecordLengthConfig) {
	this.maxRecordLengthConfig = maxRecordLengthConfig;
    }

    public void setSleepAfterMessageSent(int sleepAfterMessageSent) {
	this.sleepAfterMessageSent = sleepAfterMessageSent;
    }

    public int getSleepAfterMessageSent() {
	return sleepAfterMessageSent;
    }
}
