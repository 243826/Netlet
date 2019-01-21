package com.celeral.netlet.rpc.secure.transaction;

public interface TransactionProcessor
{
  void process(Transaction transaction);

  void process(Payload<Transaction> payload);
}
