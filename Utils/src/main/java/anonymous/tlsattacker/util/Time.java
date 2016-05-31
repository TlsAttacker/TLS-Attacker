/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.util;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class Time {

    /**
     * Unix time means number of seconds since 1970, in GMT time zone.
     * Date.getTime() returns number of milliseconds since 1970 in GMT, thus we
     * convert it to seconds.
     * 
     * @return unix time
     */
    public static final long getUnixTime() {

	// long millis = new Date().getTime();
	long sec = System.currentTimeMillis() / 1000;

	return sec;
    }
}
