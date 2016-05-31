/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.config.converters.BigIntegerConverter;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.constants.NamedCurve;
import anonymous.tlsattacker.tls.workflow.WorkflowTraceType;
import java.math.BigInteger;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class InvalidCurveAttackCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "invalid_curve";

    @Parameter(names = "-premaster_secret", description = "Premaster Secret String (use 0x at the beginning for a hex value)", converter = BigIntegerConverter.class)
    BigInteger premasterSecret;

    @Parameter(names = "-public_point_base_x", description = "Public key point coordinate X sent to the server (use 0x at the beginning for a hex value)", converter = BigIntegerConverter.class)
    BigInteger publicPointBaseX;

    @Parameter(names = "-public_point_base_y", description = "Public key point coordinate Y sent to the server (use 0x at the beginning for a hex value)", converter = BigIntegerConverter.class)
    BigInteger publicPointBaseY;

    public InvalidCurveAttackCommandConfig() {
	cipherSuites.clear();
	cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
	namedCurves.clear();
	namedCurves.add(NamedCurve.SECP256R1);
	workflowTraceType = WorkflowTraceType.HANDSHAKE;
    }

    public BigInteger getPremasterSecret() {
	return premasterSecret;
    }

    public void setPremasterSecret(BigInteger premasterSecret) {
	this.premasterSecret = premasterSecret;
    }

    public BigInteger getPublicPointBaseX() {
	return publicPointBaseX;
    }

    public void setPublicPointBaseX(BigInteger publicPointBaseX) {
	this.publicPointBaseX = publicPointBaseX;
    }

    public BigInteger getPublicPointBaseY() {
	return publicPointBaseY;
    }

    public void setPublicPointBaseY(BigInteger publicPointBaseY) {
	this.publicPointBaseY = publicPointBaseY;
    }

}
