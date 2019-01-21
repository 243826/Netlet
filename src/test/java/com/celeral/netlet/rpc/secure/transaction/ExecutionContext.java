package com.celeral.netlet.rpc.secure.transaction;

import java.io.File;

public interface ExecutionContext
{
  /**
   * Gets id of the tenant who initiated the transaction
   * @return id of the initiating tenant
   */
  long getTenantId();

  /**
   * Gets the storage root specific to the tenant
   * @return
   */
  File getStorageRoot();
}
