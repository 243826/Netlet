package com.celeral.netlet.rpc.secure.transaction;

public interface Transaction
{
  long getId();
  long getPayloadCount();
  boolean begin(ExecutionContext context);
  void end(ExecutionContext context);
}
