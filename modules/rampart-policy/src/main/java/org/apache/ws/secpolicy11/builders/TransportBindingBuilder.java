/*
 * Copyright 2001-2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ws.secpolicy11.builders;

import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.AlgorithmSuite;
import org.apache.ws.secpolicy.model.Layout;
import org.apache.ws.secpolicy.model.SupportingToken;
import org.apache.ws.secpolicy.model.TransportBinding;
import org.apache.ws.secpolicy.model.TransportToken;

public class TransportBindingBuilder implements AssertionBuilder<OMElement> {

  public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {
    TransportBinding transportBinding = new TransportBinding(SPConstants.SP_V11);

    final Policy policy = PolicyEngine.getPolicy(element.getFirstElement()).normalize(false);

    final Iterator<List<Assertion>> iterator = policy.getAlternatives();

    if (iterator.hasNext()) { // there should be max one alternative
      processAlternative(iterator.next(), transportBinding, factory);
    }

    return transportBinding;

  }

  public QName[] getKnownElements() {
    return new QName[] {SP11Constants.TRANSPORT_BINDING};
  }

  private void processAlternative(List<Assertion> assertions, TransportBinding parent, AssertionBuilderFactory factory) {

    if (assertions != null) {

      for (Assertion primitive : assertions) {

        final QName name = primitive.getName();

        if (name.equals(SP11Constants.ALGORITHM_SUITE)) {
          parent.setAlgorithmSuite((AlgorithmSuite) primitive);
        } else if (name.equals(SP11Constants.TRANSPORT_TOKEN)) {
          parent.setTransportToken(((TransportToken) primitive));
        } else if (name.equals(SP11Constants.INCLUDE_TIMESTAMP)) {
          parent.setIncludeTimestamp(true);
        } else if (name.equals(SP11Constants.LAYOUT)) {
          parent.setLayout((Layout) primitive);
        } else if (name.equals(SP11Constants.SIGNED_SUPPORTING_TOKENS)) {
          parent.setSignedSupportingToken((SupportingToken) primitive);
        } else if (name.equals(SP11Constants.SIGNED_ENDORSING_SUPPORTING_TOKENS)) {
          parent.setSignedEndorsingSupportingTokens((SupportingToken) primitive);
        }

      }

    }

  }

}
