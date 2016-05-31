/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

/**
 * Abstract Class for EAP-Frames
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public abstract class EAPFrame {
    byte[] frame;

    short eaplength;

    int tlslength;

    int id;

    public byte[] getFrame() {
	return frame;
    }

    public abstract void createFrame();

}
