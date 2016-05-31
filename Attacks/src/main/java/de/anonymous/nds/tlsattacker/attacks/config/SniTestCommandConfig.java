/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import java.util.LinkedList;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class SniTestCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "sni_test";

    @Parameter(names = "-server_name2", description = "Servername for HostName TLS extension, used in the second ClientHello message.")
    protected String serverName2;

    public SniTestCommandConfig() {
	cipherSuites = new LinkedList<>();
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
    }

    public String getServerName2() {
	return serverName2;
    }

    public void setServerName2(String serverName2) {
	this.serverName2 = serverName2;
    }
}
