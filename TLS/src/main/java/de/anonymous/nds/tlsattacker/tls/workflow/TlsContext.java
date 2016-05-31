/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import anonymous.tlsattacker.tls.constants.AlgorithmResolver;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.tls.crypto.TlsMessageDigest;
import anonymous.tlsattacker.tls.exceptions.CryptoException;
import anonymous.tlsattacker.tls.protocol.ProtocolMessageTypeHolder;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.constants.CompressionMethod;
import anonymous.tlsattacker.tls.constants.DigestAlgorithm;
import anonymous.tlsattacker.tls.constants.HandshakeByteLength;
import anonymous.tlsattacker.tls.constants.SignatureAlgorithm;
import anonymous.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import anonymous.tlsattacker.tls.record.RecordHandler;
import anonymous.tlsattacker.util.ArrayConverter;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.ServerDHParams;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class TlsContext {

    /**
     * SSL/TLS protocol version
     */
    private ProtocolVersion protocolVersion = ProtocolVersion.TLS12;
    /**
     * Indicates if we are executing a server or client
     */
    private ConnectionEnd myConnectionEnd = ConnectionEnd.CLIENT;
    /**
     * master secret established during the handshake
     */
    private byte[] masterSecret = new byte[HandshakeByteLength.MASTER_SECRET];
    /**
     * premaster secret established during the handshake
     */
    private byte[] preMasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET];
    /**
     * client random, including unix time
     */
    private byte[] clientRandom = new byte[HandshakeByteLength.RANDOM + HandshakeByteLength.UNIX_TIME];
    /**
     * server random, including unix time
     */
    private byte[] serverRandom = new byte[HandshakeByteLength.RANDOM + HandshakeByteLength.UNIX_TIME];
    /**
     * selected cipher suite
     */
    private CipherSuite selectedCipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;
    /**
     * compression algorithm
     */
    private CompressionMethod compressionMethod;
    /**
     * session ID
     */
    private byte[] sessionID = new byte[HandshakeByteLength.RANDOM + HandshakeByteLength.UNIX_TIME];
    /**
     * server certificate parsed from the server certificate message
     */
    private Certificate serverCertificate;
    /**
     * client certificate parsed from the client certificate message
     */
    private Certificate clientCertificate;
    /**
     * server certificate from the server certificate message, in a nice x509
     * form
     */
    private X509CertificateObject x509ServerCertificateObject;
    /**
     * client certificate from the client certificate message, in a nice x509
     * form
     */
    private X509CertificateObject x509ClientCertificateObject;
    /**
     * EC context containing information about public/private key agreements,
     * curves, and point formats
     */
    private TlsECContext ecContext;
    /**
     * Server DH parameters
     */
    private ServerDHParams serverDHParameters;
    /**
     * Server DH Private Key
     */
    private DHPrivateKeyParameters serverDHPrivateKeyParameters;
    /**
     * workflow trace containing all the messages exchanged during the
     * communication
     */
    @HoldsModifiableVariable
    private WorkflowTrace workflowTrace;
    /**
     * List of preconfigured protocol messages by the workflow configuration
     * factory. In case the real message order of sent messages was modified,
     * one can compare it to the preconfigured order and find differences.
     */
    private List<ProtocolMessageTypeHolder> preconfiguredProtocolMessages;
    /**
     * keystore for storing client / server certificates
     */
    private KeyStore keyStore;
    /**
     * alias for the used key in the keystore
     */
    private String alias;
    /**
     * key store password
     */
    private String password;
    /**
     * host to connect
     */
    private String host;
    /**
     * Client Authentication YES or NO
     */
    private boolean clientAuthentication = false;
    /**
     * SessionResumptionWorkflow
     */
    private boolean sessionResumption = false;
    /**
     * RenegotiationWorkflow
     */
    private boolean renegotiation = false;
    /**
     * Man_in_the_Middle_Workflow
     */
    private boolean mitm = false;

    private TlsMessageDigest digest;

    private LinkedList<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms;

    private RecordHandler recordHandler;

    /**
     * DTLS Cookie
     */
    private byte[] dtlsHandshakeCookie = new byte[0];

    public TlsContext() {
	digest = new TlsMessageDigest();
	ecContext = new TlsECContext();
    }

    public TlsContext(ProtocolVersion pv) {
	this();
	protocolVersion = pv;
    }

    public void initiliazeTlsMessageDigest() {
	try {
	    DigestAlgorithm algorithm = AlgorithmResolver.getDigestAlgorithm(protocolVersion, selectedCipherSuite);
	    digest.initializeDigestAlgorithm(algorithm);
	} catch (NoSuchAlgorithmException ex) {
	    throw new CryptoException(ex);
	}
    }

    public byte[] getMasterSecret() {
	return masterSecret;
    }

    public byte[] getServerClientRandom() {
	return ArrayConverter.concatenate(serverRandom, clientRandom);
    }

    public CipherSuite getSelectedCipherSuite() {
	return selectedCipherSuite;
    }

    public void setMasterSecret(byte[] masterSecret) {
	this.masterSecret = masterSecret;
    }

    public void setSelectedCipherSuite(CipherSuite selectedCipherSuite) {
	this.selectedCipherSuite = selectedCipherSuite;
    }

    public byte[] getClientServerRandom() {
	return ArrayConverter.concatenate(clientRandom, serverRandom);
    }

    public byte[] getPreMasterSecret() {
	return preMasterSecret;
    }

    public void setPreMasterSecret(byte[] preMasterSecret) {
	this.preMasterSecret = preMasterSecret;
    }

    public ProtocolVersion getProtocolVersion() {
	return protocolVersion;
    }

    public void setProtocolVersion(ProtocolVersion protocolVersion) {
	this.protocolVersion = protocolVersion;
    }

    public ConnectionEnd getMyConnectionEnd() {
	return myConnectionEnd;
    }

    public void setMyConnectionEnd(ConnectionEnd myConnectionEnd) {
	this.myConnectionEnd = myConnectionEnd;
    }

    public byte[] getClientRandom() {
	return clientRandom;
    }

    public void setClientRandom(byte[] clientRandom) {
	this.clientRandom = clientRandom;
    }

    public byte[] getServerRandom() {
	return serverRandom;
    }

    public void setServerRandom(byte[] serverRandom) {
	this.serverRandom = serverRandom;
    }

    public CompressionMethod getCompressionMethod() {
	return compressionMethod;
    }

    public void setCompressionMethod(CompressionMethod compressionMethod) {
	this.compressionMethod = compressionMethod;
    }

    public byte[] getSessionID() {
	return sessionID;
    }

    public void setSessionID(byte[] sessionID) {
	this.sessionID = sessionID;
    }

    public WorkflowTrace getWorkflowTrace() {
	return workflowTrace;
    }

    public void setWorkflowTrace(WorkflowTrace workflowTrace) {
	this.workflowTrace = workflowTrace;
    }

    public TlsECContext getEcContext() {
	return ecContext;
    }

    public void setEcContext(TlsECContext ecContext) {
	this.ecContext = ecContext;
    }

    public Certificate getServerCertificate() {
	return serverCertificate;
    }

    public void setServerCertificate(Certificate serverCertificate) {
	this.serverCertificate = serverCertificate;
    }

    public Certificate getClientCertificate() {
	return clientCertificate;
    }

    public void setClientCertificate(Certificate clientCertificate) {
	this.clientCertificate = clientCertificate;
    }

    public X509CertificateObject getX509ServerCertificateObject() {
	return x509ServerCertificateObject;
    }

    public void setX509ServerCertificateObject(X509CertificateObject x509ServerCertificateObject) {
	this.x509ServerCertificateObject = x509ServerCertificateObject;
    }

    public X509CertificateObject getX509ClientCertificateObject() {
	return x509ClientCertificateObject;
    }

    public void setX509ClientCertificateObject(X509CertificateObject x509ClientCertificateObject) {
	this.x509ClientCertificateObject = x509ClientCertificateObject;
    }

    public ServerDHParams getServerDHParameters() {
	return serverDHParameters;
    }

    public void setServerDHParameters(ServerDHParams serverDHParameters) {
	this.serverDHParameters = serverDHParameters;
    }

    public DHPrivateKeyParameters getServerDHPrivateKeyParameters() {
	return serverDHPrivateKeyParameters;
    }

    public void setServerDHPrivateKeyParameters(DHPrivateKeyParameters serverDHPrivateKeyParameters) {
	this.serverDHPrivateKeyParameters = serverDHPrivateKeyParameters;
    }

    public List<ProtocolMessageTypeHolder> getPreconfiguredProtocolMessages() {
	return preconfiguredProtocolMessages;
    }

    public void setPreconfiguredProtocolMessages(List<ProtocolMessageTypeHolder> preconfiguredProtocolMessages) {
	this.preconfiguredProtocolMessages = preconfiguredProtocolMessages;
    }

    public KeyStore getKeyStore() {
	return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
	this.keyStore = keyStore;
    }

    public String getAlias() {
	return alias;
    }

    public void setAlias(String alias) {
	this.alias = alias;
    }

    public String getPassword() {
	return password;
    }

    public void setPassword(String password) {
	this.password = password;
    }

    public String getHost() {
	return host;
    }

    public void setHost(String host) {
	this.host = host;
    }

    public TlsMessageDigest getDigest() {
	return digest;
    }

    public LinkedList<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
	return supportedSignatureAndHashAlgorithms;
    }

    public LinkedList<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsForRSA() {
	LinkedList<SignatureAndHashAlgorithm> rsaAlgorithms = new LinkedList<>();
	for (SignatureAndHashAlgorithm alg : supportedSignatureAndHashAlgorithms) {
	    if (alg.getSignatureAlgorithm() == SignatureAlgorithm.RSA) {
		rsaAlgorithms.add(alg);
	    }
	}
	return rsaAlgorithms;
    }

    public LinkedList<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsForEC() {
	LinkedList<SignatureAndHashAlgorithm> ecAlgorithms = new LinkedList<>();
	for (SignatureAndHashAlgorithm alg : supportedSignatureAndHashAlgorithms) {
	    if (alg.getSignatureAlgorithm() == SignatureAlgorithm.ECDSA) {
		ecAlgorithms.add(alg);
	    }
	}
	return ecAlgorithms;
    }

    public void setSupportedSignatureAndHashAlgorithms(
	    LinkedList<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
	this.supportedSignatureAndHashAlgorithms = supportedSignatureAndHashAlgorithms;
    }

    public void setDtlsHandshakeCookie(byte[] cookie) {
	this.dtlsHandshakeCookie = cookie;
    }

    public byte[] getDtlsHandshakeCookie() {
	return dtlsHandshakeCookie;
    }

    public RecordHandler getRecordHandler() {
	return recordHandler;
    }

    public void setRecordHandler(RecordHandler recordHandler) {
	this.recordHandler = recordHandler;
    }

    public boolean isClientAuthentication() {
	return clientAuthentication;
    }

    public void setClientAuthentication(boolean status) {
	this.clientAuthentication = status;
    }

    public boolean isSessionResumption() {
	return sessionResumption;
    }

    public void setSessionResumption(boolean sessionResumption) {
	this.sessionResumption = sessionResumption;
    }

    public boolean isRenegotiation() {
	return renegotiation;
    }

    public void setRenegotiation(boolean renegotiation) {
	this.renegotiation = renegotiation;
    }

    public boolean isMitMAttack() {
	return mitm;
    }

    public void setMitMAttack(boolean mitm) {
	this.mitm = mitm;
    }
}
