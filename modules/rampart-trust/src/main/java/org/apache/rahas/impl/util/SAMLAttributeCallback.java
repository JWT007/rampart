package org.apache.rahas.impl.util;

import java.util.ArrayList;
import java.util.List;

import org.apache.rahas.RahasData;


@SuppressWarnings({"UnusedDeclaration"})
public class SAMLAttributeCallback implements SAMLCallback{

  private final List<org.opensaml.saml1.core.Attribute> saml1Attributes = new ArrayList<>();

  private final List<org.opensaml.saml2.core.Attribute> saml2Attributes = new ArrayList<>();

  private final RahasData data;

  public SAMLAttributeCallback(RahasData data){
    this.data = data;
  }

  public int getCallbackType(){
    return SAMLCallback.ATTR_CALLBACK;
  }

  /**
   * Add SAML1 attribute.
   * @param attribute SAML1 attribute
   */
  public void addAttributes(org.opensaml.saml1.core.Attribute attribute){
    saml1Attributes.add(attribute);
  }

  /**
   * Overloaded  method to support SAML2
   * @param attribute SAML2 attribute.
   */
  public void addAttributes(org.opensaml.saml2.core.Attribute attribute){
    saml2Attributes.add(attribute);
  }

  /**
   * Get the array of SAML2 attributes.
   * @return SAML2 attribute list.
   */
  public org.opensaml.saml2.core.Attribute[] getSAML2Attributes(){
    return saml2Attributes.toArray(new org.opensaml.saml2.core.Attribute[0]);
  }

  /**
   * Get SAML2 attribute
   * @return SAML2 attributes.
   */
  public org.opensaml.saml1.core.Attribute[] getAttributes(){
    return saml1Attributes.toArray(new org.opensaml.saml1.core.Attribute[0]);

  }

  public RahasData getData() {
    return data;
  }

}
