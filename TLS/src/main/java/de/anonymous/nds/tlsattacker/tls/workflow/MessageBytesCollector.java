/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.util.ArrayConverter;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class MessageBytesCollector {

    private byte[] recordBytes;

    private byte[] protocolMessageBytes;

    public MessageBytesCollector() {
	this.recordBytes = new byte[0];
	this.protocolMessageBytes = new byte[0];
    }

    public byte[] getRecordBytes() {
	return recordBytes;
    }

    public void setRecordBytes(byte[] recordBytes) {
	this.recordBytes = recordBytes;
    }

    public byte[] getProtocolMessageBytes() {
	return protocolMessageBytes;
    }

    public void setProtocolMessageBytes(byte[] protocolMessageBytes) {
	this.protocolMessageBytes = protocolMessageBytes;
    }

    public void appendRecordBytes(byte[] recordBytes) {
	this.recordBytes = ArrayConverter.concatenate(this.recordBytes, recordBytes);
    }

    public void appendProtocolMessageBytes(byte[] protocolMessageBytes) {
	this.protocolMessageBytes = ArrayConverter.concatenate(this.protocolMessageBytes, protocolMessageBytes);
    }

    public void flushRecordBytes() {
	this.recordBytes = new byte[0];
    }

    public void flushProtocolMessageBytes() {
	this.protocolMessageBytes = new byte[0];
    }
}
