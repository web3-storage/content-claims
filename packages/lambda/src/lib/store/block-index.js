/* global WritableStream, TransformStream */
import { QueryCommand } from '@aws-sdk/client-dynamodb'
import { unmarshall } from '@aws-sdk/util-dynamodb'
import * as Link from 'multiformats/link'
import { base58btc } from 'multiformats/bases/base58'
import { sha256 } from 'multiformats/hashes/sha2'
import * as Digest from 'multiformats/hashes/digest'
import varint from 'varint'
import retry from 'p-retry'
import { MultihashIndexSortedWriter } from 'cardex/multihash-index-sorted'
import { Assert } from '@web3-storage/content-claims/capability'
import { fromString } from 'uint8arrays'
import { DynamoTable } from './dynamo-table.js'

/**
 * @typedef {import('@web3-storage/content-claims/server/api').ClaimFetcher} ClaimFetcher
 */

const CAR_CODE = 0x0202
const LIMIT = 10

/**
 * Materializes claims on demand using block indexes stored in DynamoDB.
 *
 * @implements {ClaimFetcher}
 */
export class BlockIndexClaimFetcher extends DynamoTable {
  #signer

  /**
   * @param {import('@aws-sdk/client-dynamodb').DynamoDBClient} client
   * @param {string} tableName
   * @param {import('@ucanto/server').Signer} signer
   */
  constructor (client, tableName, signer) {
    super(client, tableName)
    this.#signer = signer
  }

  /** @param {import('@ucanto/server').UnknownLink} content */
  async get (content) {
    const command = new QueryCommand({
      TableName: this.tableName,
      Limit: LIMIT,
      KeyConditions: {
        blockmultihash: {
          ComparisonOperator: 'EQ',
          AttributeValueList: [{ S: base58btc.encode(content.multihash.bytes) }]
        }
      },
      AttributesToGet: ['carpath', 'length', 'offset']
    })

    const result = await retry(() => this.dynamoClient.send(command), {
      minTimeout: 100,
      onFailedAttempt: err => console.warn(`failed DynamoDB query for: ${content}`, err)
    })

    const items = (result.Items ?? [])
      .map(item => {
        const { carpath, offset, length } = unmarshall(item)
        const [region, bucket, ...rest] = carpath.split('/')
        return { region, bucket, key: rest.join('/'), offset, length }
      })

    // TODO: remove when all content is copied over to R2
    let item = items.find(({ bucket }) => bucket === 'carpark-prod-0')
    item = item ?? items.find(({ bucket, key }) => bucket === 'dotstorage-prod-1' && key.startsWith('raw'))
    item = item ?? items.find(({ bucket, key }) => bucket === 'dotstorage-prod-0' && key.startsWith('raw'))
    item = item ?? items[0]
    if (!item) return []

    // can derive car cid from /raw keys. not for /complete keys
    const part = bucketKeyToPartCID(item.key)
    const location = [new URL(`https://${item.bucket}.s3.amazonaws.com/${item.key}`)]
    const expiration = Math.ceil((Date.now() / 1000) + (60 * 60)) // expire in an hour
    const claims = [
      buildLocationClaim(this.#signer, { content, location, ...item }, expiration),
      ...(part ? [buildRelationClaim(this.#signer, { content, part, ...item }, expiration)] : [])
    ]
    return Promise.all(claims)
  }
}

/**
 * @param {import('@ucanto/server').Signer} signer
 * @param {{ content: import('@ucanto/server').UnknownLink, location: URL[], offset: number, length: number }} data
 * @param {number} [expiration]
 */
const buildLocationClaim = (signer, { content, location, offset, length }, expiration) =>
  buildClaim(content, Assert.location.invoke({
    issuer: signer,
    audience: signer,
    with: signer.did(),
    nb: {
      content,
      // @ts-ignore
      location: location.map(l => l.toString()),
      range: {
        offset,
        length
      }
    },
    expiration
  }))

/**
 * @param {import('@ucanto/server').Signer} signer
 * @param {{ content: import('multiformats').UnknownLink, part: import('multiformats').Link, offset: number, length: number }} data
 * @param {number} [expiration]
 */
const buildRelationClaim = async (signer, { content, part, offset, length }, expiration) => {
  const carOffset = offset - (varint.encodingLength(content.bytes.length + length) + content.bytes.length)
  const index = await encodeIndex(content, carOffset)
  const invocation = Assert.relation.invoke({
    issuer: signer,
    audience: signer,
    with: signer.did(),
    nb: {
      content,
      children: [],
      parts: [{
        content: part,
        includes: {
          content: index.cid
        }
      }]
    },
    expiration
  })
  invocation.attach(index)
  return buildClaim(content, invocation)
}

/**
 * @param {import('@ucanto/server').UnknownLink} content
 * @param {import('@ucanto/server').IssuedInvocationView<import('@web3-storage/content-claims/server/service/api').AnyAssertCap>} invocation
 */
const buildClaim = async (content, invocation) => {
  const ipldView = await invocation.buildIPLDView()
  const archive = await ipldView.archive()
  if (!archive.ok) throw new Error('failed to archive invocation', { cause: archive.error })
  return {
    claim: ipldView.cid,
    bytes: archive.ok,
    content: content.multihash,
    expiration: ipldView.expiration,
    value: invocation.capabilities[0]
  }
}

/**
 * @param {import('@ucanto/server').UnknownLink} content
 * @param {number} offset
 */
const encodeIndex = async (content, offset) => {
  const { writable, readable } = new TransformStream()
  const writer = MultihashIndexSortedWriter.createWriter({ writer: writable.getWriter() })
  writer.add(content, offset)
  writer.close()

  /** @type {Uint8Array[]} */
  const chunks = []
  await readable.pipeTo(new WritableStream({ write: chunk => { chunks.push(chunk) } }))

  const bytes = Buffer.concat(chunks)
  const digest = await sha256.digest(bytes)
  return { cid: Link.create(MultihashIndexSortedWriter.codec, digest), bytes }
}

/**
 * Attempts to extract a CAR CID from a bucket key.
 *
 * @param {string} key
 */
const bucketKeyToPartCID = key => {
  const filename = String(key.split('/').at(-1))
  const [hash] = filename.split('.')
  try {
    // recent buckets encode CAR CID in filename
    const cid = Link.parse(hash).toV1()
    if (cid.code === CAR_CODE) return cid
    throw new Error('not a CAR CID')
  } catch (err) {
    // older buckets base32 encode a CAR multihash <base32(car-multihash)>.car
    try {
      const digestBytes = fromString(hash, 'base32')
      const digest = Digest.decode(digestBytes)
      return Link.create(CAR_CODE, digest)
    } catch {}
  }
}
