/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls;

import anonymous.tlsattacker.tls.config.CommandConfig;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @param <Config>
 */
public abstract class Attacker<Config extends CommandConfig> {

    protected Config config;

    /**
     * Tls Contexts stored for logging purposes
     */
    protected List<TlsContext> tlsContexts;

    public Attacker(Config config) {
	this.config = config;
	tlsContexts = new LinkedList<>();
    }

    /**
     * Executes a given attack
     * 
     * @param configHandler
     */
    public abstract void executeAttack(ConfigHandler configHandler);

    public Config getConfig() {
	return config;
    }

    public void setConfig(Config config) {
	this.config = config;
    }

    public List<TlsContext> getTlsContexts() {
	return tlsContexts;
    }

    public void setTlsContexts(List<TlsContext> tlsContexts) {
	this.tlsContexts = tlsContexts;
    }
}
