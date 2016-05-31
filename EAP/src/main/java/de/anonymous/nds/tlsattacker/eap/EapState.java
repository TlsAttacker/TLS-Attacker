/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

/**
 * Interface for EAP-TLS Statemachine.
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public interface EapState {

    public void send();

    public void sendTLS(byte[] tlspacket);

    public byte[] receive();

    public String getState();

    public int getID();

}
