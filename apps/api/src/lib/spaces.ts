// ============================================================================
// DO Spaces S3-compatible client utility
// ============================================================================
//
// Wraps the AWS SDK S3Client for DigitalOcean Spaces (Toronto).
// Used for file cleanup during data destruction pipeline (IMA-060).

import {
  S3Client,
  ListObjectsV2Command,
  DeleteObjectsCommand,
  type _Object,
} from '@aws-sdk/client-s3';

// ---------------------------------------------------------------------------
// Client factory
// ---------------------------------------------------------------------------

export interface SpacesConfig {
  endpoint: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  region?: string;
}

export function createSpacesClient(config: SpacesConfig): S3Client {
  return new S3Client({
    endpoint: `https://${config.endpoint}`,
    region: config.region ?? 'us-east-1', // DO Spaces requires a region but ignores the value
    credentials: {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
    },
    forcePathStyle: false,
  });
}

// ---------------------------------------------------------------------------
// Delete all objects under a prefix
// ---------------------------------------------------------------------------

export async function deleteObjectsByPrefix(
  client: S3Client,
  bucket: string,
  prefix: string,
): Promise<number> {
  let deleted = 0;
  let continuationToken: string | undefined;

  do {
    const listResponse = await client.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: continuationToken,
      }),
    );

    const objects: _Object[] = listResponse.Contents ?? [];
    if (objects.length === 0) break;

    const keys = objects
      .map((obj) => obj.Key)
      .filter((key): key is string => !!key);

    if (keys.length > 0) {
      await client.send(
        new DeleteObjectsCommand({
          Bucket: bucket,
          Delete: {
            Objects: keys.map((Key) => ({ Key })),
            Quiet: true,
          },
        }),
      );
      deleted += keys.length;
    }

    continuationToken = listResponse.IsTruncated
      ? listResponse.NextContinuationToken
      : undefined;
  } while (continuationToken);

  return deleted;
}

// ---------------------------------------------------------------------------
// Delete all provider-scoped files
// ---------------------------------------------------------------------------

const PROVIDER_PREFIXES = ['exports', 'reports', 'uploads'] as const;

export async function deleteProviderFiles(
  client: S3Client,
  bucket: string,
  providerId: string,
): Promise<{ totalDeleted: number; prefixes: Record<string, number> }> {
  const prefixes: Record<string, number> = {};
  let totalDeleted = 0;

  for (const prefix of PROVIDER_PREFIXES) {
    const count = await deleteObjectsByPrefix(
      client,
      bucket,
      `${prefix}/${providerId}/`,
    );
    prefixes[prefix] = count;
    totalDeleted += count;
  }

  return { totalDeleted, prefixes };
}

// ---------------------------------------------------------------------------
// Spaces client interface (for testability — inject in service deps)
// ---------------------------------------------------------------------------

export interface SpacesFileClient {
  deleteProviderFiles(providerId: string): Promise<{
    totalDeleted: number;
    prefixes: Record<string, number>;
  }>;
}

export function createSpacesFileClient(
  config: SpacesConfig,
): SpacesFileClient {
  const client = createSpacesClient(config);
  return {
    async deleteProviderFiles(providerId: string) {
      return deleteProviderFiles(client, config.bucket, providerId);
    },
  };
}
