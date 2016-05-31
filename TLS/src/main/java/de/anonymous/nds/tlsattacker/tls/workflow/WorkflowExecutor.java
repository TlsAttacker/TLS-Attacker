/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.tls.exceptions.WorkflowExecutionException;

/**
 * @author anonymous Pfützenreuter <anonymous.pfuetzenreuter@anonymous>
 */
public interface WorkflowExecutor {

    public void executeWorkflow() throws WorkflowExecutionException;

}
