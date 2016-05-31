/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.ec;

import anonymous.tlsattacker.tls.crypto.ec.Point;
import java.math.BigInteger;

/**
 * 
 * @author anonymous
 */
public class ICEPoint extends Point {

    private int order;

    public ICEPoint() {

    }

    public ICEPoint(int order, BigInteger x, BigInteger y) {
	super(x, y);
	this.order = order;
    }

    public int getOrder() {
	return order;
    }

    public void setOrder(int order) {
	this.order = order;
    }

    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("Point order: ").append(order).append("\nX: ").append(x).append("\nY: ").append(y);
	return sb.toString();
    }

}
