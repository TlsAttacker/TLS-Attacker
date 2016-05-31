/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

/**
 * Set EAP-TLS Statemachine in Start-State for TLS and send EAP-TLS Start out.
 * Change the State if a EAP-TLS Frame was received.
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public class EapTlsStartState implements EapState {

    EapolMachine eapolMachine;

    int id;

    EapFactory eaptlsfactory = new EapTlsFactory();

    NetworkHandler nic = NetworkHandler.getInstance();

    byte[] data = {};

    public EapTlsStartState(EapolMachine eapolMachine, int id) {

	this.eapolMachine = eapolMachine;
	this.id = id;

    }

    @Override
    public void send() {

	EAPFrame eapstart = eaptlsfactory.createFrame("EAPNAK", id);
	nic.sendFrame(eapstart.getFrame());

    }

    @Override
    public void sendTLS(byte[] tlspacket) {

    }

    @Override
    public byte[] receive() {

	data = nic.receiveFrame();
	int id = (int) data[19]; // Get ID

	if (data[22] == 0x0d) {
	    eapolMachine.setState(new HelloState(eapolMachine, id));
	} else {
	    eapolMachine.setState(new EapTlsStartState(eapolMachine, id));
	}
	return data;
    }

    @Override
    public String getState() {
	return "EapTlsStartState";
    }

    @Override
    public int getID() {

	return (int) data[19];

    }

}
