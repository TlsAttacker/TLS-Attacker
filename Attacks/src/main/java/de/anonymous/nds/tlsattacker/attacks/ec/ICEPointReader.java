/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.ec;

import anonymous.tlsattacker.tls.exceptions.ConfigurationException;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class ICEPointReader {

    static Logger LOGGER = LogManager.getLogger(ICEPointReader.class);

    private ICEPointReader() {

    }

    /**
     * Reads points for the attack on elliptic curves from a file specific for
     * this named curve
     * 
     * @param namedCurve
     * @return
     */
    public static List<ICEPoint> readPoints(String namedCurve) {
	String namedCurveLow = namedCurve.toLowerCase();
	String fileName = "points_" + namedCurveLow + ".txt";

	BufferedReader br = new BufferedReader(new InputStreamReader(ICEPointReader.class.getClassLoader()
		.getResourceAsStream(fileName)));
	String line;
	List<ICEPoint> points = new LinkedList<>();
	try {
	    while ((line = br.readLine()) != null) {
		if (line.length() != 0 && !line.startsWith("#")) {
		    String[] nums = line.split("\\s+,\\s+");
		    int order = Integer.parseInt(nums[0]);
		    BigInteger x = new BigInteger(nums[1], 16);
		    BigInteger y = new BigInteger(nums[2], 16);
		    points.add(new ICEPoint(order, x, y));
		}
	    }
	    Collections.sort(points, new ICEPointCopmparator());
	    if (LOGGER.isDebugEnabled()) {
		LOGGER.debug("Using the following curves and points");
		for (ICEPoint p : points) {
		    LOGGER.debug(p.getOrder() + " , " + p.getX().toString(16) + " , " + p.getY().toString(16));
		}
	    }
	    return points;
	} catch (IOException | NumberFormatException ex) {
	    throw new ConfigurationException(ex.getLocalizedMessage(), ex);
	}
    }
}
