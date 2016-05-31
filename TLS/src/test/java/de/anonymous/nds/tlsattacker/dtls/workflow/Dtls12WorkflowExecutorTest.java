/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.dtls.workflow;

import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.config.ClientConfigHandler;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import anonymous.tlsattacker.transport.TransportHandlerType;
import anonymous.tlsattacker.transport.UDPTransportHandler;
import anonymous.tlsattacker.util.ArrayConverter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.fail;
import org.junit.Test;

/**
 * @author anonymous Pfützenreuter <anonymous.pfuetzenreuter@anonymous>
 */
public class Dtls12WorkflowExecutorTest {

    public Dtls12WorkflowExecutorTest() {
	Security.removeProvider("SunPKCS11-NSS");
	Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testExecuteWorkflow() {
	boolean enableTest = false;

	if (enableTest) {
	    try {
		ClientCommandConfig config = new ClientCommandConfig();
		ClientConfigHandler configHandler = new ClientConfigHandler();

		config.setProtocolVersion(ProtocolVersion.DTLS12);
		config.setConnect("127.0.0.1:4444");
		config.setTransportHandlerType(TransportHandlerType.UDP);

		UDPTransportHandler th = (UDPTransportHandler) configHandler.initializeTransportHandler(config);

		DatagramSocket sender = new DatagramSocket(4444, InetAddress.getByName("127.0.0.1"));
		sender.connect(th.getLocalAddress(), th.getLocalPort());

		byte[] data = ArrayConverter
			.hexStringToByteArray("16fefd00000000000000000023030000170000000000000017feff14d87dc7"
				+ "bc151b53b31202cd1eab5f4b0d0374418e");
		DatagramPacket packet = new DatagramPacket(data, data.length);
		sender.send(packet);

		data = ArrayConverter
			.hexStringToByteArray("16fefd00000000000000010052020000460001000000000046fefd1e8caa7c1662161"
				+ "5c4ce30d3e399731fc55e68b9c2df5c244c5b95d0f83ecde620f54dd179b13e3f87cd9ea53045c48350e813bd9a2ffb3e5ed8b"
				+ "52206862f3720002f0016fefd000000000000000200780b000228000200000000006c0002250002223082021e3082018702045"
				+ "07c6eae300d06092a864886f70d01010505003056310b3009060355040613024445310c300a06035504080c034e5257310f300"
				+ "d06035504070c06426f6368756d310c300a060355040a0c03484749310c300a060355040b0c035255");
		packet = new DatagramPacket(data, data.length);
		sender.send(packet);

		data = ArrayConverter
			.hexStringToByteArray("16fefd000000000000000300d70b000228000200006c0000cb42310c300a060355040"
				+ "30c03525542301e170d3132313031353230313433385a170d3133313031353230313433385a3056310b3009060355040613024"
				+ "445310c300a06035504080c034e5257310f300d06035504070c06426f6368756d310c300a060355040a0c03484749310c300a0"
				+ "60355040b0c03525542310c300a06035504030c0352554230819f300d06092a864886f70d010101050003818d0030818902818"
				+ "10080c29bd12a9891a5824f4afa757c1bf072bcfbfdfa0f55e3522fbb510bd2699ada4d7882ddf950");
		packet = new DatagramPacket(data, data.length);
		sender.send(packet);

		data = ArrayConverter
			.hexStringToByteArray("16fefd000000000000000400d70b00022800020001370000cb328e52b31557de86237"
				+ "4d0ef7f7a2d5be57744f5dd99f25e50a785910cd588b764c600e6bc1379e815f5e25e903586c61011b3b4102ade60ce582218f"
				+ "6eb479fc671130622c21011f7f6d19f7bba2c9472578e14ca65884af30203010001300d06092a864886f70d010105050003818"
				+ "1003f9818b16ea3b2bb6dc959f127548c33bfb5edd559215530f1da4eaf461aae8201b95bcc70aa9fbc6ba5a24b2f38c135c4a"
				+ "4bf611ee340f3a2fb02b5f9df53dca8e0a39678b67104ac3fc0c2bc24343cc0f2832c2a4864b0c96d");
		packet = new DatagramPacket(data, data.length);
		sender.send(packet);

		data = ArrayConverter
			.hexStringToByteArray("16fefd000000000000000500320b0002280002000202000026f56c3151827a47f5853"
				+ "8b409d911824300bb8c1c2f2299b7830318f90ec226d2e70ce28da95416fefd0000000000000006000c0e00000000030000000"
				+ "00000");
		packet = new DatagramPacket(data, data.length);
		sender.send(packet);

		TlsContext context = WorkflowConfigurationFactory.createInstance(config).createFullTlsContext();
		context.setMyConnectionEnd(ConnectionEnd.CLIENT);
		Dtls12WorkflowExecutor workflowExecutor = new Dtls12WorkflowExecutor(th, context);
		workflowExecutor.executeWorkflow();

		sender.close();
	    } catch (Exception e) {
		fail(e.getMessage());
	    }
	}
    }
}
