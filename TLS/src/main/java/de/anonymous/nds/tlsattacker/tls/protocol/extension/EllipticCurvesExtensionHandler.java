/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol.extension;

import anonymous.tlsattacker.tls.constants.ExtensionByteLength;
import anonymous.tlsattacker.tls.constants.ExtensionType;
import anonymous.tlsattacker.tls.constants.NamedCurve;
import anonymous.tlsattacker.util.ArrayConverter;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class EllipticCurvesExtensionHandler extends ExtensionHandler<EllipticCurvesExtensionMessage> {

    private static EllipticCurvesExtensionHandler instance;

    /**
     * byte length of the supported elliptic curves length
     */
    public static final int SUPPORTED_ELLIPTIC_CURVES_LENGTH = 2;

    private EllipticCurvesExtensionHandler() {

    }

    public static EllipticCurvesExtensionHandler getInstance() {
	if (instance == null) {
	    instance = new EllipticCurvesExtensionHandler();
	}
	return instance;
    }

    /**
     * @param extension
     */
    @Override
    public void initializeClientHelloExtension(EllipticCurvesExtensionMessage extension) {
	byte[] curves = null;
	for (NamedCurve curve : extension.getSupportedCurvesConfig()) {
	    curves = ArrayConverter.concatenate(curves, curve.getValue());
	}

	extension.setExtensionType(ExtensionType.ELLIPTIC_CURVES.getValue());
	extension.setSupportedCurves(curves);
	extension.setSupportedCurvesLength(curves.length);
	extension.setExtensionLength(extension.getSupportedCurvesLength().getValue() + ExtensionByteLength.EXTENSIONS);

	byte[] ecExtensionBytes = ArrayConverter.concatenate(extension.getExtensionType().getValue(), ArrayConverter
		.intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), ArrayConverter
		.intToBytes(extension.getSupportedCurvesLength().getValue(), SUPPORTED_ELLIPTIC_CURVES_LENGTH),
		extension.getSupportedCurves().getValue());

	extension.setExtensionBytes(ecExtensionBytes);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
	throw new UnsupportedOperationException("Not supported yet.");
    }
}
