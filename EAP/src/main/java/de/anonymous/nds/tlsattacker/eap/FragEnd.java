/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

import anonymous.tlsattacker.util.ArrayConverter;

/**
 * Construct the EAP Frag End Frame with last TLS-Packet and EAP-FLag 0x00.
 * http://tools.ietf.org/html/rfc3748
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public class FragEnd extends EAPResponseDecorator {

    EAPFrame eapframe;

    byte[] tlspacket;

    public FragEnd(EAPFrame eapframe, int id, byte[] tlspacket) {
	this.eapframe = eapframe;
	this.id = id;
	this.tlspacket = tlspacket;
	createFrame();

    }

    @Override
    public byte[] getFrame() {

	return ArrayConverter.concatenate(eapframe.getFrame(), frame, tlspacket);
    }

    @Override
    public void createFrame() {

	SplitTLS fragment = SplitTLS.getInstance();

	frame = new byte[8];
	eaplength = (short) ((frame.length - 2) + tlspacket.length);
	tlslength = fragment.getSizeInt();

	frame[0] = (byte) (super.eaplength >>> 8); // Length
	frame[1] = (byte) (super.eaplength); // Length
	frame[2] = 0x02; // Code
	frame[3] = (byte) id; // ID
	frame[4] = (byte) (super.eaplength >>> 8); // Length
	frame[5] = (byte) (super.eaplength); // Length
	frame[6] = 0x0d; // Type
	frame[7] = (byte) 0x00; // EAP-Flag

    }

}
