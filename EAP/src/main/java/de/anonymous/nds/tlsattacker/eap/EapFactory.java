/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

/**
 * EAP-Factory to create EAP and EAP-TLS Frames
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public abstract class EapFactory {

    public EAPFrame getFrame(String typ, int id) {

	EAPFrame frame = createFrame(typ, id);

	return frame;
    }

    protected abstract EAPFrame createFrame(String element, int id);

    protected abstract EAPFrame createFrame(String element, int id, byte[] tlspacket);

}
