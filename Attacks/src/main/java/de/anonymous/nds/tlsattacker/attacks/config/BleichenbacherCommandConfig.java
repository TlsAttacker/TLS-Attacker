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
public class BleichenbacherCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "bleichenbacher";

    public enum Type {
	FULL,
	FAST
    }

    @Parameter(names = "-type", description = "Type of the Bleichenbacher Test results in a different number of server test quries (FAST/FULL)")
    Type type;

    public BleichenbacherCommandConfig() {
	cipherSuites = new LinkedList<>();
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
	type = Type.FAST;
    }

    public Type getType() {
	return type;
    }

    public void setType(Type type) {
	this.type = type;
    }
}
