/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.filter;

final public class ModificationFilterFactory {

    private ModificationFilterFactory() {
    }

    public static AccessModificationFilter access(final int[] accessNumbers) {
	return new AccessModificationFilter(accessNumbers);
    }
}
