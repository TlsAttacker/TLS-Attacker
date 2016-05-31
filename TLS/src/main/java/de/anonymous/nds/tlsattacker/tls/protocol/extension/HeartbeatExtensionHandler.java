/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.extension;

import anonymous.tlsattacker.tls.constants.ExtensionByteLength;
import anonymous.tlsattacker.tls.constants.ExtensionType;
import anonymous.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class HeartbeatExtensionHandler extends ExtensionHandler<HeartbeatExtensionMessage> {

    private static HeartbeatExtensionHandler instance;

    private HeartbeatExtensionHandler() {

    }

    public static HeartbeatExtensionHandler getInstance() {
	if (instance == null) {
	    instance = new HeartbeatExtensionHandler();
	}
	return instance;
    }

    @Override
    public void initializeClientHelloExtension(HeartbeatExtensionMessage extension) {
	byte[] heartbeatMode = { extension.getHeartbeatModeConfig().getValue() };

	extension.setExtensionType(ExtensionType.HEARTBEAT.getValue());
	extension.setHeartbeatMode(heartbeatMode);

	extension.setExtensionLength(extension.getHeartbeatMode().getValue().length);

	byte[] pfExtension = ArrayConverter.concatenate(extension.getExtensionType().getValue(),
		ArrayConverter.intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS),
		extension.getHeartbeatMode().getValue());

	extension.setExtensionBytes(pfExtension);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
	if (extensionMessage == null) {
	    extensionMessage = new HeartbeatExtensionMessage();
	}
	HeartbeatExtensionMessage hem = (HeartbeatExtensionMessage) extensionMessage;
	int nextPointer = pointer + ExtensionByteLength.TYPE;
	byte[] extensionType = Arrays.copyOfRange(message, pointer, nextPointer);
	hem.setExtensionType(extensionType);

	pointer = nextPointer;
	nextPointer = pointer + ExtensionByteLength.EXTENSIONS;
	int extensionLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, pointer, nextPointer));
	hem.setExtensionLength(extensionLength);

	pointer = nextPointer;
	byte[] mode = { message[pointer] };
	hem.setHeartbeatMode(mode);

	byte[] result = ArrayConverter.concatenate(hem.getExtensionType().getValue(), ArrayConverter.intToBytes(hem
		.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), hem.getHeartbeatMode().getValue());
	hem.setExtensionBytes(result);

	return pointer + 1;
    }

}
