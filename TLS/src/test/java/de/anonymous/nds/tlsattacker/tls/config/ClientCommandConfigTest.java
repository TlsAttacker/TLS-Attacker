/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ClientCommandConfigTest {

    /**
     * Test config command line parsing
     */
    @Test
    public void testCommandLineParsing() {
	JCommander jc = new JCommander(new GeneralConfig());

	ServerCommandConfig server = new ServerCommandConfig();
	jc.addCommand(ServerCommandConfig.COMMAND, server);
	ClientCommandConfig client = new ClientCommandConfig();
	jc.addCommand(ClientCommandConfig.COMMAND, client);

	jc.parse("client", "-connect", "localhost:443", "-keystore", "test.pem", "-password", "password",
		"-workflow_trace_type", "FULL");

	assertEquals("client", jc.getParsedCommand());
	assertEquals("localhost:443", client.getConnect());
	assertEquals("test.pem", client.getKeystore());
	assertEquals("password", client.getPassword());
    }

    /**
     * Test invalid config without connect parameter
     */
    @Test(expected = ParameterException.class)
    public void testInvalidCommandLineParsing() {
	JCommander jc = new JCommander();

	ClientCommandConfig client = new ClientCommandConfig();
	jc.addCommand(ClientCommandConfig.COMMAND, client);

	jc.parse("client", "-connect");
    }
}
