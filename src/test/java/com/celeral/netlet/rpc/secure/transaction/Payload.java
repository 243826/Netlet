package com.celeral.netlet.rpc.secure.transaction;

public interface Payload<T extends Transaction>
{
  long getTransactionId();
  int getSequenceId();

  boolean execute(ExecutionContext context, T transaction);
}
