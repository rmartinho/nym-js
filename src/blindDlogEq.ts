import { Point, Scalar } from '@rmf1723/ristretto255'
import { ProofError } from './proof.js'
import dlogEq, { Transcript } from './dloqEq.js'
import { Channel } from './channel.js'

export type Publics = {
  g1: Point
  h1: Point
  g2: Point
  h2: Point
}

export type Secrets = { γ: Scalar }

type Commitments = { a: Point; b: Point }
type Answer = { y: Scalar }

export async function verify(
  ch: Channel,
  { g1, h1, g2, h2 }: Publics,
  { γ }: Secrets
): Promise<Transcript> {
  const { a, b } = (await ch.receive()) as Commitments

  const α = Scalar.random()
  const β = Scalar.random()

  const a1 = a.add(α.mul(g1)).add(β.mul(h1))
  const b1 = γ.mul(b.add(α.mul(g2)).add(β.mul(h2)))
  const c_minus_β = dlogEq.nonInteractiveChallengeFor(
    {
      g1,
      h1,
      g2: γ.mul(g2),
      h2: γ.mul(h2),
    },
    a1,
    b1
  )
  const c = c_minus_β.add(β)
  await ch.send({ c })
  const { y } = (await ch.receive()) as Answer

  const ok1 = +y.mul(g1).equals(a.add(c.mul(h1)))
  const ok2 = +y.mul(g2).equals(b.add(c.mul(h2)))
  if ((ok1 & ok2) == 0) {
    throw new ProofError('blind-dlog-eq')
  }

  return {
    a: a1,
    b: b1,
    c: c_minus_β,
    y: y.add(α),
  }
}

export default {
  verify,
}
