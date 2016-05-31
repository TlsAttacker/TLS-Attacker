/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.tls.constants.ECPointFormat;
import anonymous.tlsattacker.tls.constants.NamedCurve;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class TlsECContext {
    /**
     * EC public key parameters for EC handshakes
     */
    private ECPublicKeyParameters clientPublicKeyParameters;
    /**
     * EC private key parameters
     */
    private ECPrivateKeyParameters clientPrivateKeyParameters;
    /**
     * EC public key parameters of the server
     */
    private ECPublicKeyParameters serverPublicKeyParameters;
    /**
     * supported named curves
     */
    private NamedCurve[] namedCurves;
    /**
     * supported server point formats
     */
    private ECPointFormat[] serverPointFormats;
    /**
     * supported client point formats
     */
    private ECPointFormat[] clientPointFormats;

    public void setClientPublicKeyParameters(ECPublicKeyParameters ecPublicKeyParameters) {
	this.clientPublicKeyParameters = ecPublicKeyParameters;
    }

    public ECPublicKeyParameters getClientPublicKeyParameters() {
	return clientPublicKeyParameters;
    }

    public ECPrivateKeyParameters getClientPrivateKeyParameters() {
	return clientPrivateKeyParameters;
    }

    public void setClientPrivateKeyParameters(ECPrivateKeyParameters clientPrivateKeyParameters) {
	this.clientPrivateKeyParameters = clientPrivateKeyParameters;
    }

    public NamedCurve[] getNamedCurves() {
	return namedCurves;
    }

    public void setNamedCurves(NamedCurve[] namedCurves) {
	this.namedCurves = namedCurves;
    }

    public ECPointFormat[] getServerPointFormats() {
	return serverPointFormats;
    }

    public void setServerPointFormats(ECPointFormat[] serverPointFormats) {
	this.serverPointFormats = serverPointFormats;
    }

    public ECPointFormat[] getClientPointFormats() {
	return clientPointFormats;
    }

    public void setClientPointFormats(ECPointFormat[] clientPointFormats) {
	this.clientPointFormats = clientPointFormats;
    }

    public ECPublicKeyParameters getServerPublicKeyParameters() {
	return serverPublicKeyParameters;
    }

    public void setServerPublicKeyParameters(ECPublicKeyParameters serverPublicKeyParameters) {
	this.serverPublicKeyParameters = serverPublicKeyParameters;
    }

}
