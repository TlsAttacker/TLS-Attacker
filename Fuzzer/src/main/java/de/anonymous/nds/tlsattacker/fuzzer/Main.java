/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.fuzzer;

import com.beust.jcommander.JCommander;
import anonymous.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import anonymous.tlsattacker.attacks.config.DtlsPaddingOracleAttackCommandConfig;
import anonymous.tlsattacker.attacks.config.InvalidCurveAttackCommandConfig;
import anonymous.tlsattacker.attacks.config.InvalidCurveAttackFullCommandConfig;
import anonymous.tlsattacker.attacks.config.HeartbleedCommandConfig;
import anonymous.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import anonymous.tlsattacker.attacks.config.PoodleCommandConfig;
import anonymous.tlsattacker.attacks.config.WinshockCommandConfig;
import anonymous.tlsattacker.attacks.impl.BleichenbacherAttack;
import anonymous.tlsattacker.attacks.impl.DtlsPaddingOracleAttack;
import anonymous.tlsattacker.attacks.impl.InvalidCurveAttack;
import anonymous.tlsattacker.attacks.impl.InvalidCurveAttackFull;
import anonymous.tlsattacker.attacks.impl.HeartbleedAttack;
import anonymous.tlsattacker.attacks.impl.PaddingOracleAttack;
import anonymous.tlsattacker.attacks.impl.PoodleAttack;
import anonymous.tlsattacker.attacks.impl.WinshockAttack;
import anonymous.tlsattacker.fuzzer.config.MultiFuzzerConfig;
import anonymous.tlsattacker.fuzzer.impl.MultiFuzzer;
import anonymous.tlsattacker.tls.Attacker;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.config.ConfigHandlerFactory;
import anonymous.tlsattacker.tls.config.GeneralConfig;
import anonymous.tlsattacker.tls.exceptions.ConfigurationException;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class Main {

    public static void main(String[] args) throws Exception {

	GeneralConfig generalConfig = new GeneralConfig();
	JCommander jc = new JCommander(generalConfig);

	MultiFuzzerConfig cmconfig = new MultiFuzzerConfig();
	jc.addCommand(MultiFuzzerConfig.COMMAND, cmconfig);

	BleichenbacherCommandConfig bleichenbacherTest = new BleichenbacherCommandConfig();
	jc.addCommand(BleichenbacherCommandConfig.ATTACK_COMMAND, bleichenbacherTest);
	DtlsPaddingOracleAttackCommandConfig dtlsPaddingOracleAttackTest = new DtlsPaddingOracleAttackCommandConfig();
	jc.addCommand(DtlsPaddingOracleAttackCommandConfig.ATTACK_COMMAND, dtlsPaddingOracleAttackTest);
	// EarlyCCSCommandConfig earlyCCS = new EarlyCCSCommandConfig();
	// jc.addCommand(EarlyCCSCommandConfig.COMMAND, earlyCCS);
	InvalidCurveAttackCommandConfig ellipticTest = new InvalidCurveAttackCommandConfig();
	jc.addCommand(InvalidCurveAttackCommandConfig.ATTACK_COMMAND, ellipticTest);
	InvalidCurveAttackFullCommandConfig elliptic = new InvalidCurveAttackFullCommandConfig();
	jc.addCommand(InvalidCurveAttackFullCommandConfig.ATTACK_COMMAND, elliptic);
	HeartbleedCommandConfig heartbleed = new HeartbleedCommandConfig();
	jc.addCommand(HeartbleedCommandConfig.ATTACK_COMMAND, heartbleed);
	PaddingOracleCommandConfig paddingOracle = new PaddingOracleCommandConfig();
	jc.addCommand(PaddingOracleCommandConfig.ATTACK_COMMAND, paddingOracle);
	PoodleCommandConfig poodle = new PoodleCommandConfig();
	jc.addCommand(PoodleCommandConfig.ATTACK_COMMAND, poodle);
	// SniTestCommandConfig sniTest = new SniTestCommandConfig();
	// jc.addCommand(SniTestCommandConfig.COMMAND, sniTest);
	WinshockCommandConfig winshock = new WinshockCommandConfig();
	jc.addCommand(WinshockCommandConfig.ATTACK_COMMAND, winshock);

	jc.parse(args);

	if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
	    jc.usage();
	    return;
	}

	Attacker attacker;
	switch (jc.getParsedCommand()) {
	    case MultiFuzzerConfig.COMMAND:
		startMultiFuzzer(cmconfig, generalConfig, jc);
		return;
	    case BleichenbacherCommandConfig.ATTACK_COMMAND:
		attacker = new BleichenbacherAttack(bleichenbacherTest);
		break;
	    // case EarlyCCSCommandConfig.COMMAND:
	    // attacker = new EarlyCCSAttack(earlyCCS);
	    // break;
	    case InvalidCurveAttackCommandConfig.ATTACK_COMMAND:
		attacker = new InvalidCurveAttack(ellipticTest);
		break;
	    case InvalidCurveAttackFullCommandConfig.ATTACK_COMMAND:
		attacker = new InvalidCurveAttackFull(elliptic);
		break;
	    case HeartbleedCommandConfig.ATTACK_COMMAND:
		attacker = new HeartbleedAttack(heartbleed);
		break;
	    case PoodleCommandConfig.ATTACK_COMMAND:
		attacker = new PoodleAttack(poodle);
		break;
	    case PaddingOracleCommandConfig.ATTACK_COMMAND:
		attacker = new PaddingOracleAttack(paddingOracle);
		break;
	    case WinshockCommandConfig.ATTACK_COMMAND:
		attacker = new WinshockAttack(winshock);
		break;
	    case DtlsPaddingOracleAttackCommandConfig.ATTACK_COMMAND:
		attacker = new DtlsPaddingOracleAttack(dtlsPaddingOracleAttackTest);
		break;
	    // case SniTestCommandConfig.COMMAND:
	    // attacker = new SniTest(sniTest);
	    // break;
	    default:
		throw new ConfigurationException("No command found");
	}
	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initialize(generalConfig);

	if (configHandler.printHelpForCommand(jc, attacker.getConfig())) {
	    return;
	}

	attacker.executeAttack(configHandler);

    }

    private static void startMultiFuzzer(MultiFuzzerConfig fuzzerConfig, GeneralConfig generalConfig, JCommander jc) {
	MultiFuzzer fuzzer = new MultiFuzzer(fuzzerConfig, generalConfig);
	if (fuzzerConfig.isHelp()) {
	    jc.usage(MultiFuzzerConfig.COMMAND);
	    return;
	}
	fuzzer.startFuzzer();
    }
}
