/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ServerCommandConfigTest {

    /**
     * Test config command line parsing
     */
    @Test
    public void testCommandLineParsing() {
	JCommander jc = new JCommander();

	ServerCommandConfig server = new ServerCommandConfig();
	jc.addCommand(ServerCommandConfig.COMMAND, server);
	ClientCommandConfig client = new ClientCommandConfig();
	jc.addCommand(ClientCommandConfig.COMMAND, client);

	jc.parse("server", "-servername_fatal", "-keystore", "test.pem", "-password", "password");

	assertEquals("server", jc.getParsedCommand());
	assertTrue(server.isServerNameFatal());
	assertEquals("test.pem", server.getKeystore());
	assertEquals("password", server.getPassword());

	jc.parse("server", "-cipher", "TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA", "-version",
		"TLSv1.2");

	assertEquals("server", jc.getParsedCommand());
	assertEquals(2, server.getCipherSuites().size());
	assertEquals(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, server.getCipherSuites().get(0));
	assertEquals(ProtocolVersion.TLS12, server.getProtocolVersion());
    }

    /**
     * Test invalid config with invalid cipher suite
     */
    @Test(expected = ParameterException.class)
    public void testInvalidCommandLineParsing() {
	JCommander jc = new JCommander();

	ServerCommandConfig server = new ServerCommandConfig();
	jc.addCommand(ServerCommandConfig.COMMAND, server);

	jc.parse("server", "-cipher", "invalid,TLS_RSA_WITH_AES_256_CBC_SHA", "-version", "TLSv1.2");
    }

}
