import { Point, Scalar } from '@rmf1723/ristretto255'
import schnorrkel, {
  PublicKey,
  SecretKey,
  Signature,
  SignatureError,
  SigningContext,
} from '@rmf1723/schnorrkel'
import dlogEq from './dloqEq.js'
import { ACCEPT } from './proof.js'
import { Channel } from './channel.js'
import { Nym } from './nym.js'

export class UserSecretKey {
  #key: SecretKey

  constructor(key: SecretKey) {
    this.#key = key
  }

  static random(): UserSecretKey {
    const seed = schnorrkel.randomKeySeed()
    return new UserSecretKey(schnorrkel.expandKey(seed))
  }

  get publicKey(): UserPublicKey {
    return new UserPublicKey(this.#key.publicKey)
  }

  get exponent(): Scalar {
    return this.#key.exponent
  }

  signWithNym(nym: Nym, context: SigningContext): Signature {
    context.appendMessage('proto-name', 'Nym-sig')
    context.appendMessage('sign:nym/a', nym.a.toBytes())
    context.appendMessage('sign:nym/b', nym.b.toBytes())

    const r = Scalar.fromHash(
      context
        .buildRng()
        .rekeyWithWitnessBytes('signing', this.#key.nonce)
        .finalize()
        .fillBytes(64)
    )
    const R = r.mul(nym.a)
    context.appendMessage('sign:R', R.toBytes())

    const k = Scalar.fromHash(context.challengeBytes('sign:c', 64))
    const s = k.mul(this.#key.exponent).add(r)

    return new Signature(R, s)
  }
}

export class UserPublicKey {
  #key: PublicKey

  constructor(key: PublicKey) {
    this.#key = key
  }

  get point(): Point {
    return this.#key.point
  }

  verifyWithNym(
    nym: Nym,
    context: SigningContext,
    sig: Signature
  ): typeof ACCEPT {
    context.appendMessage('proto-name', 'Nym-sig')
    context.appendMessage('sign:nym/a', nym.a.toBytes())
    context.appendMessage('sign:nym/b', nym.b.toBytes())
    context.appendMessage('sign:R', sig.R.toBytes())

    const k = Scalar.fromHash(context.challengeBytes('sign:c', 64))
    const R = k.mul(nym.b.mul(Scalar.ONE.negate())).add(sig.s.mul(nym.a))

    if (!R.equals(sig.R)) {
      throw new SignatureError()
    }

    return ACCEPT
  }
}

export class OrgSecretKey {
  #key1: SecretKey
  #key2: SecretKey

  constructor(key1: SecretKey, key2: SecretKey) {
    this.#key1 = key1
    this.#key2 = key2
  }

  static random(): OrgSecretKey {
    const seed1 = schnorrkel.randomKeySeed()
    const seed2 = schnorrkel.randomKeySeed()
    return new OrgSecretKey(
      schnorrkel.expandKey(seed1),
      schnorrkel.expandKey(seed2)
    )
  }

  get publicKey(): OrgPublicKey {
    return new OrgPublicKey(this.#key1.publicKey, this.#key2.publicKey)
  }

  get exponents(): [Scalar, Scalar] {
    return [this.#key1.exponent, this.#key2.exponent]
  }

  async proveOwnership(ch: Channel): Promise<void> {
    await proveOwnershipOf(ch, this.#key1)
    await proveOwnershipOf(ch, this.#key2)
  }
}

export class OrgPublicKey {
  #key1: PublicKey
  #key2: PublicKey

  constructor(key1: PublicKey, key2: PublicKey) {
    this.#key1 = key1
    this.#key2 = key2
  }

  get points(): [Point, Point] {
    return [this.#key1.point, this.#key2.point]
  }

  async verifyOwnership(ch: Channel): Promise<typeof ACCEPT> {
    await verifyOwnershipOf(ch, this.#key1)
    return verifyOwnershipOf(ch, this.#key2)
  }
}

function proveOwnershipOf(ch: Channel, key: SecretKey) {
  return dlogEq.prove(
    ch,
    {
      g1: Point.BASE,
      h1: key.publicKey.point,
      g2: Point.BASE,
      h2: key.publicKey.point,
    },
    { x: key.exponent }
  )
}
function verifyOwnershipOf(ch: Channel, key: PublicKey) {
  return dlogEq.verify(ch, {
    g1: Point.BASE,
    h1: key.point,
    g2: Point.BASE,
    h2: key.point,
  })
}
