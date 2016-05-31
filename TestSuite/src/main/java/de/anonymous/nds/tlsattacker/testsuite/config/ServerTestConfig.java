/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.testsuite.config;

import com.beust.jcommander.Parameter;
import anonymous.tlsattacker.tls.config.ClientCommandConfig;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ServerTestConfig extends ClientCommandConfig {

    public static final String COMMAND = "testsuite_server";

    @Parameter(names = "-folder", description = "Root folder including the test cases.")
    String folder;

    public ServerTestConfig() {
	folder = "../resources/testsuite";
    }

    public String getFolder() {
	return folder;
    }

    public void setFolder(String folder) {
	this.folder = folder;
    }
}
