/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * State for the end of a Fragmentation. Change state if a CCS, Alert or Failure
 * was received.
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public class FragEndState implements EapState {

    private static final Logger LOGGER = LogManager.getLogger(FragEndState.class);

    EapolMachine eapolMachine;

    int id;

    EapFactory eaptlsfactory = new EapTlsFactory();

    NetworkHandler nic = NetworkHandler.getInstance();

    byte[] data = {};

    public FragEndState(EapolMachine eapolMachine, int id) {

	this.eapolMachine = eapolMachine;
	this.id = id;

    }

    @Override
    public void send() {
	// TODO Auto-generated method stub

    }

    @Override
    public void sendTLS(byte[] tlspacket) {

	EAPFrame eapstart = eaptlsfactory.createFrame("EAPTLSFRAG", id, tlspacket);

	LOGGER.debug("sendTLS(): {}", eapolMachine.getState());

	nic.sendFrame(eapstart.getFrame());

    }

    @Override
    public byte[] receive() {

	data = nic.receiveFrame();
	id = (int) data[19]; // Get ID

	LOGGER.debug("receive() TLS-FLAG: {}", Byte.toString(data[23]));

	if (data[18] == 0x04) {
	    eapolMachine.setState(new FailureState(eapolMachine, id));
	    LOGGER.debug("change State to: {}", eapolMachine.getState());
	} else if (data[28] == (byte) 0x14) {
	    // Change Chipher Spec vom Server empfangen?
	    LOGGER.debug("receive() TLS Content Type: {}", Byte.toString(data[28]));
	    eapolMachine.setState(new FinishedState(eapolMachine, id));
	    LOGGER.debug("change State to: {}", eapolMachine.getState());

	} else if (data[28] == (byte) 0x15) {
	    // Eine AlertMessage vom Server empfangen?
	    LOGGER.debug("receive() TLS Content Type: {}", Byte.toString(data[28]));
	    eapolMachine.setState(new AlertState(eapolMachine, id));
	    LOGGER.debug("change State to: {}", eapolMachine.getState());

	}
	return data;
    }

    @Override
    public String getState() {
	return "FragEndState";

    }

    @Override
    public int getID() {

	return id;

    }

}
