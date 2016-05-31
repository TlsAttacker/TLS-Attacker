/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.extension;

import anonymous.tlsattacker.tls.constants.ExtensionByteLength;
import anonymous.tlsattacker.tls.constants.ExtensionType;
import anonymous.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import anonymous.tlsattacker.util.ArrayConverter;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class SignatureAndHashAlgorithmsExtensionHandler extends
	ExtensionHandler<SignatureAndHashAlgorithmsExtensionMessage> {

    private static SignatureAndHashAlgorithmsExtensionHandler instance;

    public static final int SIGNATURE_AND_HASH_ALGORITHMS_LENGTH = 2;

    private SignatureAndHashAlgorithmsExtensionHandler() {

    }

    public static SignatureAndHashAlgorithmsExtensionHandler getInstance() {
	if (instance == null) {
	    instance = new SignatureAndHashAlgorithmsExtensionHandler();
	}
	return instance;
    }

    /**
     * @param extension
     */
    @Override
    public void initializeClientHelloExtension(SignatureAndHashAlgorithmsExtensionMessage extension) {
	byte[] algorithms = null;
	for (SignatureAndHashAlgorithm algorithm : extension.getSignatureAndHashAlgorithmsConfig()) {
	    algorithms = ArrayConverter.concatenate(algorithms, algorithm.getByteValue());
	}

	extension.setExtensionType(ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS.getValue());
	extension.setSignatureAndHashAlgorithms(algorithms);
	extension.setSignatureAndHashAlgorithmsLength(algorithms.length);
	extension.setExtensionLength(extension.getSignatureAndHashAlgorithmsLength().getValue()
		+ ExtensionByteLength.EXTENSIONS);

	byte[] extensionBytes = ArrayConverter.concatenate(extension.getExtensionType().getValue(), ArrayConverter
		.intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), ArrayConverter
		.intToBytes(extension.getSignatureAndHashAlgorithmsLength().getValue(),
			SIGNATURE_AND_HASH_ALGORITHMS_LENGTH), extension.getSignatureAndHashAlgorithms().getValue());

	extension.setExtensionBytes(extensionBytes);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
	throw new UnsupportedOperationException("Not supported yet.");
    }
}
