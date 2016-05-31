/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package anonymous.tlsattacker.testsuite.impl;

import anonymous.tlsattacker.tls.config.GeneralConfig;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public abstract class TestSuite {

    GeneralConfig generalConfig;

    public TestSuite(GeneralConfig config) {
	this.generalConfig = config;
    }

    public abstract boolean startTests();
}
