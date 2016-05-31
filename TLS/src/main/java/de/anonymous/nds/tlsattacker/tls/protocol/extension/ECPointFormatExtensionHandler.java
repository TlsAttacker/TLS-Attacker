/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.extension;

import anonymous.tlsattacker.tls.constants.ECPointFormat;
import anonymous.tlsattacker.tls.constants.ExtensionByteLength;
import anonymous.tlsattacker.tls.constants.ExtensionType;
import anonymous.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ECPointFormatExtensionHandler extends ExtensionHandler<ECPointFormatExtensionMessage> {

    private static ECPointFormatExtensionHandler instance;

    /**
     * byte length of the ec point format length
     */
    public static final int EC_POINT_FORMATS_LENGTH = 1;

    private ECPointFormatExtensionHandler() {

    }

    public static ECPointFormatExtensionHandler getInstance() {
	if (instance == null) {
	    instance = new ECPointFormatExtensionHandler();
	}
	return instance;
    }

    @Override
    public void initializeClientHelloExtension(ECPointFormatExtensionMessage extension) {
	byte[] pointFormats = null;
	for (ECPointFormat format : extension.getPointFormatsConfig()) {
	    pointFormats = ArrayConverter.concatenate(pointFormats, format.getArrayValue());
	}

	extension.setExtensionType(ExtensionType.EC_POINT_FORMATS.getValue());
	extension.setPointFormats(pointFormats);
	extension.setPointFormatsLength(pointFormats.length);
	extension.setExtensionLength(extension.getPointFormatsLength().getValue() + EC_POINT_FORMATS_LENGTH);

	byte[] pfExtension = ArrayConverter.concatenate(extension.getExtensionType().getValue(),
		ArrayConverter.intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS),
		ArrayConverter.intToBytes(extension.getPointFormatsLength().getValue(), EC_POINT_FORMATS_LENGTH),
		extension.getPointFormats().getValue());

	extension.setExtensionBytes(pfExtension);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {

	// todo add message handling with modified values, add tls context
	// handling

	if (extensionMessage == null) {
	    extensionMessage = new ECPointFormatExtensionMessage();
	}

	int nextPointer = pointer + ExtensionByteLength.TYPE;
	byte[] extensionType = Arrays.copyOfRange(message, pointer, nextPointer);
	extensionMessage.setExtensionType(extensionType);

	pointer = nextPointer;
	nextPointer = pointer + ExtensionByteLength.EXTENSIONS;
	int extensionLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, pointer, nextPointer));
	extensionMessage.setExtensionLength(extensionLength);

	pointer = nextPointer;
	nextPointer++;
	int ecPointFormatsLength = message[pointer];

	ECPointFormat[] pointFormats = new ECPointFormat[ecPointFormatsLength];
	pointer = nextPointer;
	for (int i = 0; i < ecPointFormatsLength; i++) {
	    pointFormats[i] = ECPointFormat.getECPointFormat(message[pointer]);
	    pointer++;
	}

	return pointer;
    }

}
