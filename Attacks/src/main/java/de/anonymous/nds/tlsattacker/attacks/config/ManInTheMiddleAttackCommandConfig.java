/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import anonymous.tlsattacker.tls.config.ClientCommandConfig;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ManInTheMiddleAttackCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "mitm";

    @Parameter(names = "-port", description = "ServerPort")
    protected String port = "4433";

    @Parameter(names = "-modify", description = "Modify the whole Workflow ")
    protected boolean modify = false;

    public String getPort() {
	return port;
    }

    public void setPort(String port) {
	this.port = port;
    }

    public boolean isModify() {
	return modify;
    }

    public void setModify(boolean modify) {
	this.modify = modify;
    }
}
