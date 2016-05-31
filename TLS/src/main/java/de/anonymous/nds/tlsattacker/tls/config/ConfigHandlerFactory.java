/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ConfigHandlerFactory {

    private ConfigHandlerFactory() {

    }

    public static ConfigHandler createConfigHandler(String command) {
	switch (command) {
	    case ClientCommandConfig.COMMAND:
		return new ClientConfigHandler();
	    case ServerCommandConfig.COMMAND:
		return new ServerConfigHandler();
	    default:
		throw new UnsupportedOperationException("You have to select one of the available commands");

	}
    }
}
