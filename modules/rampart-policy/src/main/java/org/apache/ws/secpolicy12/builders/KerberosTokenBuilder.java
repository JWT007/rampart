/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ws.secpolicy12.builders;

import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.KerberosToken;

/**
 * Builder for {@link KerberosToken} assertion (WS Security Policy version 1.2)
 */
public class KerberosTokenBuilder implements AssertionBuilder<OMElement> {

  public Assertion build(OMElement element, AssertionBuilderFactory arg1) throws IllegalArgumentException {

    final KerberosToken kerberosToken = new KerberosToken(SPConstants.SP_V12);

    final OMElement policyElement = element.getFirstElement();

    // Process token inclusion
    final OMAttribute includeAttr = element.getAttribute(SP12Constants.INCLUDE_TOKEN);

    if (includeAttr != null) {

      final int inclusion = SP12Constants.getInclusionFromAttributeValue(includeAttr.getAttributeValue());

      kerberosToken.setInclusion(inclusion);

    }

    if (policyElement != null) {

      final Policy policy = PolicyEngine.getPolicy(element.getFirstElement()).normalize(false);

      final Iterator<List<Assertion>> alternatives = policy.getAlternatives();

      if (alternatives.hasNext()) {  // there should be max one alternative
        processAlternative(alternatives.next(), kerberosToken);
      }

    }

    return kerberosToken;

  }

  private void processAlternative(List<Assertion> assertions, KerberosToken parent) {

    if (assertions != null) {

      for (Assertion assertion : assertions) {

        final QName name = assertion.getName();

        if (SP12Constants.REQUIRE_KERBEROS_V5_TOKEN_11.equals(name)) {
          parent.setRequiresKerberosV5Token(true);
        } else if (SP12Constants.REQUIRE_KERBEROS_GSS_V5_TOKEN_11.equals(name)) {
          parent.setRequiresGssKerberosV5Token(true);
        } else if (SP12Constants.REQUIRE_KEY_IDENTIFIRE_REFERENCE.equals(name)) {
          parent.setRequiresKeyIdentifierReference(true);
        }

      }

    }

  }

  public QName[] getKnownElements() {

    return new QName[] { SP12Constants.KERBEROS_TOKEN };

  }

}
