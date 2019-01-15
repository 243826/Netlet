package com.celeral.netlet.rpc.secure.transaction;

import java.io.File;

public interface ExecutionContext<T>
{
  /**
   * Gets id of the tenant who initiated the transaction
   * @return id of the initiating tenant
   */
  long getTenantId();

  int getCount();

  /**
   * Gets the actual transaction
   * @return
   */
  Transaction<?> getTransaction();


  Boolean getSequenceStatus(int id);

  /**
   * Gets the storage root specific to the tenant
   * @return
   */
  File getStorageRoot();

  /**
   * process transaction specific data.
   * @param data
   */
  void data(T data);

  /**
   * get the transaction specific data stored earlier.
   * @return
   */
  T data();
}
