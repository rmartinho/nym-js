export const ACCEPT = 'ACCEPT' as const

export class ProofError extends Error {
  constructor(proofName: string) {
    super(`${proofName} proof failure`)
    this.name = 'ProofError'
  }
}
