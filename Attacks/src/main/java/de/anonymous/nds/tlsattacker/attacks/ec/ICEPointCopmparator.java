/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.ec;

import java.util.Comparator;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class ICEPointCopmparator implements Comparator<ICEPoint> {

    @Override
    public int compare(ICEPoint o1, ICEPoint o2) {
	return Integer.compare(o1.getOrder(), o2.getOrder());
    }

}
