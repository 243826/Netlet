package com.celeral.netlet.rpc.secure.upload;

import java.io.File;
import java.io.RandomAccessFile;

public class UploadTransactionData
{
  RandomAccessFile channel;
  File tempFile;

  /* count of the processed data blocks */
  long count;

  UploadTransactionData(File temp, RandomAccessFile channel)
  {
    this.tempFile = temp;
    this.channel = channel;
  }
}
