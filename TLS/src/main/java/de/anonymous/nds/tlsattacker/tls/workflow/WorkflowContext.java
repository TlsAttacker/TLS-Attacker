/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class WorkflowContext {

    private int protocolMessagePointer;

    private boolean proceedWorkflow;

    public WorkflowContext() {
	protocolMessagePointer = 0;
	proceedWorkflow = true;
    }

    public int getProtocolMessagePointer() {
	return protocolMessagePointer;
    }

    public void setProtocolMessagePointer(int protocolMessagePointer) {
	this.protocolMessagePointer = protocolMessagePointer;
    }

    public boolean isProceedWorkflow() {
	return proceedWorkflow;
    }

    public void setProceedWorkflow(boolean proceedWorkflow) {
	this.proceedWorkflow = proceedWorkflow;
    }

    public void incrementProtocolMessagePointer() {
	protocolMessagePointer++;
    }

    public void decrementProtocolMessagePointer() {
	protocolMessagePointer--;
    }
}
