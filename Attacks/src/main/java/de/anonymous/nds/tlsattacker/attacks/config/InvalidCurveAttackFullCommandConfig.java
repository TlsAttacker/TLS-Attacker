/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import anonymous.tlsattacker.attacks.ec.ICEAttacker;
import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.constants.NamedCurve;
import anonymous.tlsattacker.tls.workflow.WorkflowTraceType;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class InvalidCurveAttackFullCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "invalid_curve_full";

    @Parameter(names = "-additional_equations", description = "Additional equations used when attacking Oracle JSSE server (needed because of a faulty JSSE implementation).")
    protected int additionalEquations;

    @Parameter(names = "-server_type", description = "Allows to switch between a normal vulnerable server type and an Oracle server type (for oracle a slightly different algorithm is needed).")
    protected ICEAttacker.ServerType serverType;

    public InvalidCurveAttackFullCommandConfig() {
	cipherSuites.clear();
	cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
	namedCurves.clear();
	namedCurves.add(NamedCurve.SECP256R1);
	workflowTraceType = WorkflowTraceType.HANDSHAKE;
	additionalEquations = 3;
	serverType = ICEAttacker.ServerType.NORMAL;
    }

    public int getAdditionalEquations() {
	return additionalEquations;
    }

    public void setAdditionalEquations(int additionalEquations) {
	this.additionalEquations = additionalEquations;
    }

    public ICEAttacker.ServerType getServerType() {
	return serverType;
    }

    public void setServerType(ICEAttacker.ServerType serverType) {
	this.serverType = serverType;
    }

}
