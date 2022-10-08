/*
 * Copyright 2004,2005 The Apache Software Foundation.
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

package org.apache.ws.secpolicy.model;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.axiom.om.OMXMLParserWrapper;
import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.ws.secpolicy.SPConstants;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class SecpolicyModelTest {

  @Test
  public void testSymmBinding() throws Exception {

    Policy policy = this.getPolicy("test-resources/policy-symm-binding.xml");

    List<Assertion> assertions = policy.getAlternatives().next();

    boolean symmBindingFound = false;

    for (Assertion assertion : assertions) {

      if (assertion instanceof SymmetricBinding) {
        symmBindingFound = true;
        SymmetricBinding binding = (SymmetricBinding) assertion;

        assertTrue(binding.isIncludeTimestamp(), "IncludeTimestamp assertion not processed");

        ProtectionToken protectionToken = binding.getProtectionToken();

        assertNotNull(protectionToken, "ProtectionToken missing");

        Token token = protectionToken.getProtectionToken();

        if (token instanceof X509Token) {

          assertEquals(SPConstants.WSS_X509_V3_TOKEN10,
                       ((X509Token) token).getTokenVersionAndType(),
                       "incorrect X509 token versin and type");

        } else {

          fail("ProtectionToken must contain a X509Token assertion");

        }


      }
    }
    //The Asymm binding mean is not built in the policy processing :-(
    assertTrue(symmBindingFound, "SymmetricBinding not processed");

  }

  @Test
  public void testAsymmBinding() throws Exception {
    this.getPolicy("test-resources/policy-asymm-binding.xml");
  }

  @Test
  public void testTransportBinding() throws Exception {
    this.getPolicy("test-resources/policy-transport-binding.xml");
  }

  @Test
  public void testSymmBindingWithBothProtectionTokenAndEncryptionToken() throws Exception {

    assertThrows(IllegalArgumentException.class,
                 () -> this.getPolicy("test-resources/policy-symm-binding-fault1.xml"),
                 "Policy cannot contain both ProtectionToken and EncryptionToken.");

  }

  private Policy getPolicy(String filePath) throws Exception {
    OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(Files.newInputStream(Paths.get(filePath)));
    OMElement elem = builder.getDocumentElement();
    return PolicyEngine.getPolicy(elem);
  }

}
