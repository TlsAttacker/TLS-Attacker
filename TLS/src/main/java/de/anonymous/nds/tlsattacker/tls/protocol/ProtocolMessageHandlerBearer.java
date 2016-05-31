/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol;

import anonymous.tlsattacker.tls.workflow.TlsContext;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public interface ProtocolMessageHandlerBearer {

    public abstract ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext);
}
