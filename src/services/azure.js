// src/services/azure.js
import { BlobServiceClient } from "@azure/storage-blob";

/**
 * Very basic URL check for Azure Blob
 */
export function isValidBlobUrl(url) {
  try {
    return url && url.includes(".blob.core.windows.net/");
  } catch {
    return false;
  }
}

// (Optional) If later you want backend upload support:
export async function uploadToAzure(containerSasUrl, blobName, buffer, contentType = "application/octet-stream") {
  const container = new BlobServiceClient(containerSasUrl).getContainerClient();
  const blockBlobClient = container.getBlockBlobClient(blobName);

  await blockBlobClient.uploadData(buffer, {
    blobHTTPHeaders: { blobContentType: contentType },
  });

  return blockBlobClient.url;
}
