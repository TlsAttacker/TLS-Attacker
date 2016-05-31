/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

/**
 * Abstract Class for EAP-Response Decorator
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public abstract class EAPResponseDecorator extends EAPFrame {

    @Override
    public abstract byte[] getFrame();

    @Override
    public abstract void createFrame();
}
