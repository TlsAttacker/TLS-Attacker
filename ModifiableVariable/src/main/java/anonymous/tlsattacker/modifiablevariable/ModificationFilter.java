/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable;

import anonymous.tlsattacker.modifiablevariable.filter.AccessModificationFilter;
import javax.xml.bind.annotation.XmlSeeAlso;

/**
 * It is possible to filter modifications only for specific number of data
 * accesses or specific data. For example, only the first data access returns a
 * modified value. This can be achieved using a ModificationFilter object.
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
@XmlSeeAlso({ AccessModificationFilter.class })
public abstract class ModificationFilter {

    public abstract boolean filterModification();
}
