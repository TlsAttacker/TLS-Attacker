/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

/**
 * Construct the 802.1x Start-Header with Version
 * https://standards.ieee.org/findstds/standard/802.1X-2010.html
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public class Start8021X extends EAPFrame {

    byte version;

    public Start8021X(byte version) {

	this.version = version;
	createFrame();

    }

    @Override
    public void createFrame() {

	frame = new byte[4];
	frame[0] = version; // Version
	frame[1] = 0x01; // Type:Start
	frame[2] = 0x00;
	frame[3] = 0x00; // Length

    }

}
