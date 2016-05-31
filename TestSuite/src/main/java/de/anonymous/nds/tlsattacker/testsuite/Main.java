/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.testsuite;

import com.beust.jcommander.JCommander;
import anonymous.tlsattacker.testsuite.config.ServerTestConfig;
import anonymous.tlsattacker.testsuite.impl.ServerTestSuite;
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

	ServerTestConfig stconfig = new ServerTestConfig();
	jc.addCommand(ServerTestConfig.COMMAND, stconfig);

	jc.parse(args);

	if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
	    jc.usage();
	    return;
	}

	switch (jc.getParsedCommand()) {
	    case ServerTestConfig.COMMAND:
		ServerTestSuite st = new ServerTestSuite(stconfig, generalConfig);
		st.startTests();
		return;

	    default:
		throw new ConfigurationException("No command found");
	}

    }
}
