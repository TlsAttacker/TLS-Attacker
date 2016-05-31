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

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ServerNameIndicationExtensionHandler extends ExtensionHandler<ServerNameIndicationExtensionMessage> {

    private static ServerNameIndicationExtensionHandler instance;

    /**
     * Server Name list length
     */
    public static final int SERVER_NAME_LIST_LENGTH = 2;

    /**
     * Server Name length
     */
    public static final int SERVER_NAME_LENGTH = 2;

    private ServerNameIndicationExtensionHandler() {

    }

    public static ServerNameIndicationExtensionHandler getInstance() {
	if (instance == null) {
	    instance = new ServerNameIndicationExtensionHandler();
	}
	return instance;
    }

    @Override
    public void initializeClientHelloExtension(ServerNameIndicationExtensionMessage extension) {
	byte serverNameType = extension.getNameTypeConfig().getValue();
	byte[] serverName = extension.getServerNameConfig().getBytes();

	extension.setExtensionType(ExtensionType.SERVER_NAME_INDICATION.getValue());
	extension.setServerNameType(serverNameType);
	extension.setServerName(serverName);
	extension.setServerNameLength(extension.getServerName().getValue().length);

	extension.setServerNameLength(extension.getServerNameLength().getValue());
	extension.setServerNameListLength(1 + SERVER_NAME_LIST_LENGTH + extension.getServerNameLength().getValue());

	extension.setExtensionLength(SERVER_NAME_LIST_LENGTH + extension.getServerNameListLength().getValue());

	byte[] sniExtension = ArrayConverter.concatenate(extension.getExtensionType().getValue(), ArrayConverter
		.intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), ArrayConverter
		.intToBytes(extension.getServerNameListLength().getValue(), SERVER_NAME_LIST_LENGTH),
		new byte[] { extension.getServerNameType().getValue() }, ArrayConverter.intToBytes(extension
			.getServerNameLength().getValue(), SERVER_NAME_LENGTH), extension.getServerName().getValue());

	extension.setExtensionBytes(sniExtension);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
	throw new UnsupportedOperationException("Not supported yet.");
    }

}
