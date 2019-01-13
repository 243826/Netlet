package com.celeral.netlet.rpc.secure;

public interface TransactionProcessor
{
  void process(Transaction<?> transaction);
  void process(Payload<?> payload);
}
