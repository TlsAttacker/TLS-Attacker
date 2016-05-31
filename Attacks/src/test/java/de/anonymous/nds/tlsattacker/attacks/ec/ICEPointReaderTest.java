/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.ec;

import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class ICEPointReaderTest {

    /**
     * Test of readPoints method, of class ICEPointReader.
     */
    @Test
    public void testReadPoints() throws Exception {
	String namedCurve = "secp192r1";
	List<ICEPoint> result = ICEPointReader.readPoints(namedCurve);

	assertEquals(5, result.get(0).getOrder());
    }

}
