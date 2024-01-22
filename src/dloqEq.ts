import { Point, Scalar } from '@rmf1723/ristretto255'
import { Transcript as MerlinTranscript } from '@rmf1723/merlin'
import { ACCEPT, ProofError } from './proof.js'
import { Channel } from './channel.js'

export type Publics = {
  g1: Point
  h1: Point
  g2: Point
  h2: Point
}

export type Secrets = {
  x: Scalar
}

export type Transcript = {
  a: Point
  b: Point
  c: Scalar
  y: Scalar
}

type Commitments = { a: Point; b: Point }
type Challenge = { c: Scalar }
type Answer = { y: Scalar }

export async function prove(
  ch: Channel,
  { g1, g2 }: Publics,
  { x }: Secrets
): Promise<void> {
  const r = Scalar.random()
  const a = r.mul(g1)
  const b = r.mul(g2)
  await ch.send({ a, b })
  const { c } = (await ch.receive()) as Challenge
  const y = r.add(x.mul(c))
  await ch.send({ y })
}

async function verifyI(
  ch: Channel,
  { g1, h1, g2, h2 }: Publics
): Promise<typeof ACCEPT> {
  const { a, b } = (await ch.receive()) as Commitments
  const c = Scalar.random()
  await ch.send({ c })
  const { y } = (await ch.receive()) as Answer
  const ok1 = +y.mul(g1).equals(a.add(c.mul(h1)))
  const ok2 = +y.mul(g2).equals(b.add(c.mul(h2)))
  if ((ok1 & ok2) == 0) {
    throw new ProofError('dlog-eq')
  }
  return ACCEPT
}

function verifyNI(
  { a, b, c, y }: Transcript,
  { g1, h1, g2, h2 }: Publics
): typeof ACCEPT {
  const okC = +c.equals(nonInteractiveChallengeFor({ g1, h1, g2, h2 }, a, b))
  const okA = +y.mul(g1).equals(a.add(c.mul(h1)))
  const okB = +y.mul(g2).equals(b.add(c.mul(h2)))
  if ((okC & okA & okB) == 0) {
    throw new ProofError('dlog-eq')
  }
  return ACCEPT
}

export function verify(ch: Channel, publics: Publics): Promise<typeof ACCEPT>
export function verify(transcript: Transcript, publics: Publics): typeof ACCEPT

export function verify(
  channelOrTranscript: Channel | Transcript,
  publics: Publics
): Promise<typeof ACCEPT> | typeof ACCEPT {
  if ('send' in channelOrTranscript) {
    const ch = channelOrTranscript as Channel
    return verifyI(ch, publics)
  } else {
    const transcript = channelOrTranscript as Transcript
    return verifyNI(transcript, publics)
  }
}

export function nonInteractiveChallengeFor(
  { g1, h1, g2, h2 }: Publics,
  a: Point,
  b: Point
): Scalar {
  const h = new MerlinTranscript(
    'nym/0.1/dlog-eq-proof/non-interactive-challenge'
  )
  h.appendMessage('g1', g1.toBytes())
  h.appendMessage('h1', h1.toBytes())
  h.appendMessage('g2', g2.toBytes())
  h.appendMessage('h2', h2.toBytes())
  h.appendMessage('a', a.toBytes())
  h.appendMessage('b', b.toBytes())
  return Scalar.fromHash(h.challengeBytes('c', 64))
}

export default {
  prove,
  verify,
  nonInteractiveChallengeFor,
}
