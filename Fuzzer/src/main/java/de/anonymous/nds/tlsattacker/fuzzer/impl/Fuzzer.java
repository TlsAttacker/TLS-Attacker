/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.fuzzer.impl;

import anonymous.tlsattacker.tls.config.GeneralConfig;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public abstract class Fuzzer {

    GeneralConfig generalConfig;

    public Fuzzer(GeneralConfig config) {
	this.generalConfig = config;
    }

    /**
     * Starts fuzzing, should be implemented in every fuzzer
     */
    public abstract void startFuzzer();
}
