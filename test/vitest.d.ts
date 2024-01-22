import { Point } from '@rmf1723/ristretto255'

declare global {
  namespace jest {
    interface Matchers<R> {
      toEqualPoint(expected: Point): R
    }
  }
}

export {}
