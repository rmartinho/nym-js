import { Point, Scalar } from '@rmf1723/ristretto255'
import dlogEq, { Transcript } from './dloqEq.js'
import {
  OrgPublicKey,
  OrgSecretKey,
  UserPublicKey,
  UserSecretKey,
} from './keys.js'
import { Channel } from './channel.js'
import { ACCEPT, ProofError } from './proof.js'
import blindDlogEq from './blindDlogEq.js'

export interface Cred {
  a: Point
  b: Point
  A: Point
  B: Point
  T1: Transcript
  T2: Transcript
}

export interface Nym {
  a: Point
  b: Point
}

export type NymOptions = Partial<{
  withCA: boolean
  forKey: UserPublicKey
}>

export class User {
  #sk: UserSecretKey

  constructor(sk: UserSecretKey) {
    this.#sk = sk
  }

  get publicKey() {
    return this.#sk.publicKey
  }

  generateNym(ch: Channel): Promise<Nym>
  generateNym(ch: Channel, opts: NymOptions): Promise<Nym>
  async generateNym(ch: Channel, opts?: NymOptions) {
    const a_ = opts?.withCA ? Point.BASE : Point.random()
    const b_ = this.#sk.exponent.mul(a_)
    return this.#generateNym(ch, a_, b_)
  }

  async #generateNym(ch: Channel, a_: Point, b_: Point) {
    await ch.send({ a_, b_ })
    const { a } = (await ch.receive()) as { a: Point }
    const b = this.#sk.exponent.mul(a)
    ch.send({ b })
    await dlogEq.prove(
      ch,
      { g1: a, h1: b, g2: a_, h2: b_ },
      { x: this.#sk.exponent }
    )
    return { a, b }
  }

  async authenticateNym(ch: Channel, nym: Nym): Promise<void> {
    await dlogEq.prove(
      ch,
      { g1: nym.a, h1: nym.b, g2: nym.a, h2: nym.b },
      { x: this.#sk.exponent }
    )
  }

  async issueCredential(
    ch: Channel,
    nym: Nym,
    sourceKey: OrgPublicKey
  ): Promise<Cred> {
    const { A, B } = (await ch.receive()) as { A: Point; B: Point }
    const γ = Scalar.random()
    const T1 = await blindDlogEq.verify(
      ch,
      {
        g1: Point.BASE,
        h1: sourceKey.points[1],
        g2: nym.b,
        h2: A,
      },
      { γ }
    )
    const T2 = await blindDlogEq.verify(
      ch,
      {
        g1: Point.BASE,
        h1: sourceKey.points[0],
        g2: nym.a.add(A),
        h2: B,
      },
      { γ }
    )

    return {
      a: nym.a.mul(γ),
      b: nym.b.mul(γ),
      A: A.mul(γ),
      B: B.mul(γ),
      T1,
      T2,
    }
  }

  async transferCredential(ch: Channel, nym: Nym, cred: Cred) {
    return dlogEq.prove(
      ch,
      { g1: nym.a, h1: nym.b, g2: cred.a, h2: cred.b },
      { x: this.#sk.exponent }
    )
  }
}

export class Org {
  #sk: OrgSecretKey

  constructor(sk: OrgSecretKey) {
    this.#sk = sk
  }

  get publicKey() {
    return this.#sk.publicKey
  }

  generateNym(ch: Channel): Promise<Nym>
  generateNym(ch: Channel, opts: NymOptions): Promise<Nym>
  async generateNym(ch: Channel, opts?: NymOptions) {
    const { a_, b_ } = (await ch.receive()) as { a_: Point; b_: Point }
    if (opts?.forKey) {
      if (!a_.equals(Point.BASE) || !b_.equals(opts.forKey.point)) {
        throw new ProofError('generate-nym')
      }
    }
    const r = Scalar.random()
    const a = r.mul(a_)
    await ch.send({ a })
    const { b } = (await ch.receive()) as { b: Point }
    await dlogEq.verify(ch, { g1: a, h1: b, g2: a_, h2: b_ })
    return { a, b }
  }

  async authenticateNym(ch: Channel, nym: Nym): Promise<typeof ACCEPT> {
    return dlogEq.verify(ch, { g1: nym.a, h1: nym.b, g2: nym.a, h2: nym.b })
  }

  async issueCredential(ch: Channel, nym: Nym): Promise<void> {
    const A = this.#sk.exponents[1].mul(nym.b)
    const B = this.#sk.exponents[0].mul(nym.a.add(A))
    await ch.send({ A, B })

    await dlogEq.prove(
      ch,
      {
        g1: Point.BASE,
        h1: this.publicKey.points[1],
        g2: nym.b,
        h2: A,
      },
      { x: this.#sk.exponents[1] }
    )
    await dlogEq.prove(
      ch,
      {
        g1: Point.BASE,
        h1: this.publicKey.points[0],
        g2: nym.a.add(A),
        h2: B,
      },
      { x: this.#sk.exponents[0] }
    )
  }

  async transferCredential(
    ch: Channel,
    nym: Nym,
    cred: Cred,
    sourceKey: OrgPublicKey
  ) {
    dlogEq.verify(cred.T1, {
      g1: Point.BASE,
      h1: sourceKey.points[1],
      g2: cred.b,
      h2: cred.A,
    })
    dlogEq.verify(cred.T2, {
      g1: Point.BASE,
      h1: sourceKey.points[0],
      g2: cred.a.add(cred.A),
      h2: cred.B,
    })
    return dlogEq.verify(ch, { g1: nym.a, h1: nym.b, g2: cred.a, h2: cred.b })
  }
}

export * from './keys.js'
export * from './proof.js'
export * from './channel.js'
