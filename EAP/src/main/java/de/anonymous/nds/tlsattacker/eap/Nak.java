/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

import anonymous.tlsattacker.util.ArrayConverter;

/**
 * Construct the NAK EAP-Frame for changing Authentication to EAP-TLS.
 * http://tools.ietf.org/html/rfc3748
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public class Nak extends EAPResponseDecorator {
    EAPFrame eapframe;

    public Nak(EAPFrame eapframe, int id) {
	this.eapframe = eapframe;
	this.id = id;
	createFrame();

    }

    @Override
    public byte[] getFrame() {

	return ArrayConverter.concatenate(eapframe.getFrame(), frame);
    }

    @Override
    public void createFrame() {

	frame = new byte[8];
	eaplength = (short) (frame.length - 2);

	frame[0] = (byte) (super.eaplength >>> 8); // Length
	frame[1] = (byte) (super.eaplength); // Length
	frame[2] = 0x02; // Code
	frame[3] = (byte) id; // ID muss aus dem ConnectionHandler kommen //ID
	frame[4] = (byte) (super.eaplength >>> 8); // Length
	frame[5] = (byte) (super.eaplength); // Length
	frame[6] = 0x03; // Type
	frame[7] = 0x0d; // Desired Auth Type

    }

}
