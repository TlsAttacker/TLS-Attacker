/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.extension;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @param <Message>
 */
public abstract class ExtensionHandler<Message extends ExtensionMessage> {

    Message extensionMessage;

    public abstract void initializeClientHelloExtension(Message extension);

    public abstract int parseExtension(byte[] message, int pointer);

    public ExtensionMessage getExtensionMessage() {
	return extensionMessage;
    }

    public void setExtensionMessage(Message extensionMessage) {
	this.extensionMessage = extensionMessage;
    }
}
