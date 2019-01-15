package com.celeral.netlet.rpc.secure.transaction;

public interface Payload<T>
{
  long getTransactionId();
  int getSequenceId();
  void execute(ExecutionContext<T> context);
}
