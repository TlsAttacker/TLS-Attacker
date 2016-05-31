/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

/**
 * State for Identity. Sends the Identity Frame. Change state if a Client Hello,
 * EAP-TLS Start or Failure Frame was received.
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public class IdentityState implements EapState {

    EapolMachine eapolMachine;

    int id;

    EapFactory eaptlsfactory = new EapTlsFactory();

    NetworkHandler nic = NetworkHandler.getInstance();

    byte[] data = {};

    public IdentityState(EapolMachine eapolMachine, int id) {

	this.eapolMachine = eapolMachine;
	this.id = id;
    }

    @Override
    public void send() {

	EAPFrame eapstart = eaptlsfactory.createFrame("EAPID", id);
	nic.sendFrame(eapstart.getFrame());

    }

    @Override
    public void sendTLS(byte[] tlspacket) {

    }

    @Override
    public byte[] receive() {

	data = nic.receiveFrame();
	id = (int) data[19]; // Get ID

	if (data[22] == 0x0d) {
	    eapolMachine.setState(new HelloState(eapolMachine, id));
	} else if (data[18] == 0x04) {
	    eapolMachine.setState(new FailureState(eapolMachine, id));
	} else {
	    eapolMachine.setState(new EapTlsStartState(eapolMachine, id));
	}
	return data;

    }

    @Override
    public String getState() {
	return "IdentityState";
    }

    @Override
    public int getID() {

	return id;

    }

}
