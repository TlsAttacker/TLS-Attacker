/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

/**
 * EAP-Constants: Multicast L2 Address, Ethernet-Type 802.1x Authentication
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public final class EapConstants {

    /** Broadcast address of EAP packet */
    public static final byte[] BROADCAST_ADDRESS = { (byte) 0x01, (byte) 0x80, (byte) 0xc2, (byte) 0x00, (byte) 0x00,
	    (byte) 0x03 };

    /** EAP packet frame type */
    public static final byte[] ETHERTYPE_EAP = { (byte) 0x88, (byte) 0x8e };

}
