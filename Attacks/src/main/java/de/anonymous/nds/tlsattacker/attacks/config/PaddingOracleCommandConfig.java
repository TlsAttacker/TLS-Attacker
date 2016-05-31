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
public class PaddingOracleCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "padding_oracle";

    @Parameter(names = "-block_size", description = "Block size of the to be used block cipher")
    Integer blockSize = 16;

    public PaddingOracleCommandConfig() {
	cipherSuites = new LinkedList<>();
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
    }

    public Integer getBlockSize() {
	return blockSize;
    }

    public void setBlockSize(Integer blockSize) {
	this.blockSize = blockSize;
    }

}
