/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

/**
 * State for the start of a Fragmentation. Change state if a Frag or Fragend
 * Frame was received.
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public class FragStartState implements EapState {

    EapolMachine eapolMachine;

    int id;

    EapFactory eaptlsfactory = new EapTlsFactory();

    NetworkHandler nic = NetworkHandler.getInstance();

    EAPFrame eapstart;

    byte[] data = {};

    public FragStartState(EapolMachine eapolMachine, int id) {

	this.eapolMachine = eapolMachine;
	this.id = id;

    }

    @Override
    public void send() {

	eapstart = eaptlsfactory.createFrame("EAPTLSFRAGACK", id);
	nic.sendFrame(eapstart.getFrame());

    }

    @Override
    public void sendTLS(byte[] tlspacket) {

	eapstart = eaptlsfactory.createFrame("EAPTLSFRAG", id, tlspacket);
	nic.sendFrame(eapstart.getFrame());

    }

    @Override
    public byte[] receive() {
	data = nic.receiveFrame();
	id = (int) data[19]; // Get ID

	if (data[23] == (byte) 0xc0 || data[23] == (byte) 0x40) {
	    eapolMachine.setState(new FragStartState(eapolMachine, id));
	} else if (data[23] == (byte) 0x00) {
	    eapolMachine.setState(new FragEndState(eapolMachine, id));
	} else {
	    eapolMachine.setState(new FragState(eapolMachine, id, 1));
	}
	return data;
    }

    @Override
    public String getState() {
	return "FragStartState";
    }

    @Override
    public int getID() {

	return id;

    }

}
