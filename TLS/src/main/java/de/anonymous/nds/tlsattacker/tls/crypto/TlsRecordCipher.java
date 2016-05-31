/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.crypto;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public abstract class TlsRecordCipher {

    /**
     * minimalRecordLength an encrypted record should have
     */
    int minimalEncryptedRecordLength;

    public abstract void init();

    public int getMinimalEncryptedRecordLength() {
	return minimalEncryptedRecordLength;
    }

    public void setMinimalEncryptedRecordLength(int minimalEncryptedRecordLength) {
	this.minimalEncryptedRecordLength = minimalEncryptedRecordLength;
    }

}
