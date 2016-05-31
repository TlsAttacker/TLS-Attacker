/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.mlong;

import anonymous.tlsattacker.modifiablevariable.VariableModification;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
@XmlRootElement
@XmlType(propOrder = { "explicitValue", "modificationFilter", "postModification" })
public class LongExplicitValueModification extends VariableModification<Long> {

    private Long explicitValue;

    public LongExplicitValueModification() {

    }

    public LongExplicitValueModification(Long bi) {
	this.explicitValue = bi;
    }

    @Override
    protected Long modifyImplementationHook(final Long input) {
	return explicitValue;
    }

    public Long getExplicitValue() {
	return explicitValue;
    }

    public void setExplicitValue(Long explicitValue) {
	this.explicitValue = explicitValue;
    }
}
