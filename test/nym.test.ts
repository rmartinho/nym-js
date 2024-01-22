/// <reference path="vitest.d.ts" />

import { test, expect } from 'vitest'
import { Sema } from 'async-sema'
import { Point } from '@rmf1723/ristretto255'
import { SignatureError, SigningContext } from '@rmf1723/schnorrkel'
import { User, UserSecretKey, Org, OrgSecretKey } from '../src/nym'
import { Channel, Message } from '../src/channel'
import { ACCEPT, ProofError } from '../src/proof'
import dlogEq from '../src/dloqEq'

test('key ownership', async () => {
  const [uch, och] = makeTestChannels()

  const osk = OrgSecretKey.random()
  const opk = osk.publicKey

  const u1 = opk.verifyOwnership(uch)
  const o1 = osk.proveOwnership(och)

  const ok = Promise.all([u1, o1]).then(x => x[0])
  await expect(ok).resolves.toEqual(ACCEPT)

  const u2 = opk.verifyOwnership(uch)
  const o2 = OrgSecretKey.random().proveOwnership(och)

  const err = Promise.all([u2, o2])
  await expect(err).rejects.toThrow(ProofError)
})

test('nym generation', async () => {
  const [uch, och] = makeTestChannels()

  const usk = UserSecretKey.random()
  const user = new User(usk)
  const osk = OrgSecretKey.random()
  const org = new Org(osk)

  const u = user.generateNym(uch)
  const o = org.generateNym(och)

  const [nu, no] = await Promise.all([u, o])

  expect(nu.a).toEqualPoint(no.a)
  expect(nu.b).toEqualPoint(no.b)
  expect(nu.a.mul(usk.exponent)).toEqualPoint(nu.b)
})

test('CA nym generation', async () => {
  const [uch, och] = makeTestChannels()

  const usk = UserSecretKey.random()
  const user = new User(usk)
  const osk = OrgSecretKey.random()
  const org = new Org(osk)

  const u1 = user.generateNym(uch, { withCA: true })
  const o1 = org.generateNym(och, { forKey: usk.publicKey })

  const [nu, no] = await Promise.all([u1, o1])

  expect(nu.a).toEqualPoint(no.a)
  expect(nu.b).toEqualPoint(no.b)
  expect(nu.a.mul(usk.exponent)).toEqualPoint(nu.b)

  const u2 = user.generateNym(uch)
  const o2 = org.generateNym(och, { forKey: usk.publicKey })

  const err = Promise.all([u2, o2])
  await expect(err).rejects.toThrow(ProofError)
})

test('nym authentication', async () => {
  const [uch, och] = makeTestChannels()

  const usk = UserSecretKey.random()
  const user = new User(usk)
  const osk = OrgSecretKey.random()
  const org = new Org(osk)

  const [nym] = await Promise.all([user.generateNym(uch), org.generateNym(och)])

  const u1 = user.authenticateNym(uch, nym)
  const o1 = org.authenticateNym(och, nym)

  const v1 = Promise.all([o1, u1]).then(([x]) => x)
  await expect(v1).resolves.toEqual(ACCEPT)

  const u2 = user.authenticateNym(uch, { a: Point.random(), b: Point.random() })
  const o2 = org.authenticateNym(och, nym)

  const v2 = Promise.all([u2, o2])
  await expect(v2).rejects.toThrow(ProofError)
})

test('credential issuing', async () => {
  const [uch, och] = makeTestChannels()

  const usk = UserSecretKey.random()
  const user = new User(usk)
  const osk = OrgSecretKey.random()
  const org = new Org(osk)

  const [nym] = await Promise.all([user.generateNym(uch), org.generateNym(och)])

  const u1 = user.issueCredential(uch, nym, osk.publicKey)
  const o1 = org.issueCredential(och, nym)

  const [cred] = await Promise.all([u1, o1])

  expect(cred.a.mul(usk.exponent)).toEqualPoint(cred.b)
  expect(cred.b.mul(osk.exponents[1])).toEqualPoint(cred.A)
  expect(cred.a.add(cred.A).mul(osk.exponents[0])).toEqualPoint(cred.B)
  expect(() =>
    dlogEq.verify(cred.T1, {
      g1: Point.BASE,
      h1: osk.publicKey.points[1],
      g2: cred.b,
      h2: cred.A,
    })
  ).not.toThrow()
  expect(() =>
    dlogEq.verify(cred.T2, {
      g1: Point.BASE,
      h1: osk.publicKey.points[0],
      g2: cred.a.add(cred.A),
      h2: cred.B,
    })
  ).not.toThrow()
})

test('credential transfer', async () => {
  const [uch, och] = makeTestChannels()

  const usk = UserSecretKey.random()
  const user = new User(usk)
  const osk1 = OrgSecretKey.random()
  const org1 = new Org(osk1)
  const osk2 = OrgSecretKey.random()
  const org2 = new Org(osk2)

  const [nym] = await Promise.all([
    user.generateNym(uch),
    org1.generateNym(och),
  ])
  const [cred] = await Promise.all([
    user.issueCredential(uch, nym, osk1.publicKey),
    org1.issueCredential(och, nym),
  ])

  const u1 = user.transferCredential(uch, nym, cred)
  const o1 = org2.transferCredential(och, nym, cred, osk1.publicKey)

  const ok = Promise.all([o1, u1]).then(x => x[0])
  await expect(ok).resolves.toEqual(ACCEPT)

  const u2 = user.transferCredential(uch, nym, cred)
  const o2 = org2.transferCredential(
    och,
    nym,
    cred,
    OrgSecretKey.random().publicKey
  )

  const err = Promise.all([o2, u2]).then(x => x[0])
  await expect(err).rejects.toThrow(ProofError)
})

test('signing with nym', async () => {
  const [uch, och] = makeTestChannels()

  const usk = UserSecretKey.random()
  const user = new User(usk)
  const osk = OrgSecretKey.random()
  const org = new Org(osk)

  const [nym] = await Promise.all([user.generateNym(uch), org.generateNym(och)])

  const ctx = new SigningContext('test')
  ctx.appendMessage('thisisatest', 'somemessage')
  const sig = usk.signWithNym(nym, ctx.clone())

  expect(() => usk.publicKey.verifyWithNym(nym, ctx.clone(), sig)).not.toThrow()

  ctx.appendMessage('ohno', 'messagewaschanged')
  expect(() => usk.publicKey.verifyWithNym(nym, ctx.clone(), sig)).toThrow(
    SignatureError
  )
})

// --- test utils ---

function makeTestChannel(): Channel {
  const msg = <any[]>[]
  const sema = new Sema(0)
  return {
    async send<Label extends Exclude<string, Label>, T>(
      message: Message<Label, T>
    ): Promise<void> {
      msg.push(message)
      sema.release()
    },
    async receive<Label extends Exclude<string, Label>, T>(): Promise<
      Message<Label, T>
    > {
      await sema.acquire()
      const message = msg.shift()
      return message
    },
  }
}

function makeTestChannels(): [Channel, Channel] {
  const channel1 = makeTestChannel()
  const channel2 = makeTestChannel()
  return [
    {
      send: m => channel1.send(m),
      receive: () => channel2.receive(),
    },
    {
      send: m => channel2.send(m),
      receive: () => channel1.receive(),
    },
  ]
}
