package org.apache.rahas.impl.util;

import org.opensaml.common.SAMLException;

/**
 * SAMLCallback Handler enables you to add data to the SAMLAssertion.
 * <p>
 * For example Assertions, NameIdentifiers.
 * </p>
 */
public interface SAMLCallbackHandler {

  /**
   * SAMLCallback object has indicates what kind of data is required.
   * if(callback.getCallbackType() == SAMLCallback.ATTR_CALLBACK)
   * {
   *     SAMLAttributeCallback attrCallback = (SAMLAttributeCallback)callback;
   *     \//Retrieve required data from the RahasData inside SAMLAttributeCallback
   *     \//Add your SAMLAttributes to the attrCallback here.
   * }
   * @param callback the callback
   * @throws SAMLException on error
   */
  void handle(SAMLCallback callback) throws SAMLException;

}
