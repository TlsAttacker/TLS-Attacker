/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.transport;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class TransportHandlerFactory {

    private TransportHandlerFactory() {

    }

    public static TransportHandler createTransportHandler() {
	return new SimpleTransportHandler();
    }

    public static TransportHandler createTransportHandler(TransportHandlerType type, int tlsTimeout) {
	switch (type) {
	    case TCP:
		SimpleTransportHandler th = new SimpleTransportHandler();
		th.setTlsTimeout(tlsTimeout);
		return th;
	    case EAP_TLS:
		return new EAPTLSTransportHandler();
	    case UDP:
		UDPTransportHandler udpth = new UDPTransportHandler();
		udpth.setTlsTimeout(tlsTimeout);
		return udpth;
	    default:
		throw new UnsupportedOperationException("This transport handler " + "type is not supported");
	}
    }
}
