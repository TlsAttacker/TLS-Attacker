/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.util;

import java.util.Random;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class RandomHelper {

    private static Random random;

    private RandomHelper() {
    }

    public static Random getRandom() {
	if (random == null) {
	    random = new Random();
	}
	return random;
    }
}
