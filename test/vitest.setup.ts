import { Point } from '@rmf1723/ristretto255'
import { expect } from 'vitest'

expect.extend({
  toEqualPoint(received: Point, expected: Point) {
    const pass: boolean = received.equals(expected)
    return {
      pass,
      expected,
      received,
      message: () =>
        `${this.utils.matcherHint(
          'toEqualPoint',
          'received',
          'expected',
          this
        )}`,
    }
  },
})
