// Rank-1 Constraint System (R1CS) for Arithmetic Circuits
// Represents computations as a system of constraints: (A * w) o (B * w) = (C * w)
// where w is the witness vector: [1, out, x_1, x_2, ..., sym_1, ...]

export type Vector = number[];
export type Matrix = Vector[];

export interface R1CSConstraint {
  description: string;
  a: Vector;
  b: Vector;
  c: Vector;
}

export interface R1CSSystem {
  variableNames: string[]; // e.g. ["1", "out", "x", "sym1", "sym2"]
  constraints: R1CSConstraint[];
}

export class R1CSEngine {
  static dotProduct(vec: Vector, w: Vector): number {
    let sum = 0;
    for (let i = 0; i < Math.min(vec.length, w.length); i++) {
      sum += vec[i] * w[i];
    }
    return sum;
  }

  static verifyWitness(system: R1CSSystem, witness: Vector): {
    satisfied: boolean;
    constraintResults: {
      index: number;
      description: string;
      aEval: number;
      bEval: number;
      cEval: number;
      satisfied: boolean;
    }[];
  } {
    let allSatisfied = true;
    const results = [];

    for (let i = 0; i < system.constraints.length; i++) {
      const c = system.constraints[i];
      const aVal = this.dotProduct(c.a, witness);
      const bVal = this.dotProduct(c.b, witness);
      const cVal = this.dotProduct(c.c, witness);
      const satisfied = Math.abs(aVal * bVal - cVal) < 1e-6;

      if (!satisfied) allSatisfied = false;

      results.push({
        index: i,
        description: c.description,
        aEval: aVal,
        bEval: bVal,
        cEval: cVal,
        satisfied,
      });
    }

    return {
      satisfied: allSatisfied,
      constraintResults: results,
    };
  }

  // Pre-configured circuit: Cubic equation x^3 + x + 5 = out
  // Witness: [1, out, x, sym1, sym2]
  // where sym1 = x * x (x^2)
  // sym2 = sym1 * x (x^3)
  // Constraint 1: x * x = sym1 -> (x) * (x) = (sym1)
  // Constraint 2: sym1 * x = sym2 -> (sym1) * (x) = (sym2)
  // Constraint 3: (sym2 + x + 5) * 1 = out -> (sym2 + x + 5*1) * (1) = (out)
  static createCubicPolynomialCircuit(): R1CSSystem {
    const variableNames = ['1', 'out', 'x', 'sym1', 'sym2'];
    // indices: 0: 1, 1: out, 2: x, 3: sym1, 4: sym2

    return {
      variableNames,
      constraints: [
        {
          description: 'sym1 = x * x',
          a: [0, 0, 1, 0, 0],
          b: [0, 0, 1, 0, 0],
          c: [0, 0, 0, 1, 0],
        },
        {
          description: 'sym2 = sym1 * x',
          a: [0, 0, 0, 1, 0],
          b: [0, 0, 1, 0, 0],
          c: [0, 0, 0, 0, 1],
        },
        {
          description: 'out = sym2 + x + 5',
          a: [5, 0, 1, 0, 1], // 5*1 + 1*x + 1*sym2
          b: [1, 0, 0, 0, 0], // * 1
          c: [0, 1, 0, 0, 0], // = out
        },
      ],
    };
  }

  static generateCubicWitness(x: number): { witness: Vector; out: number } {
    const sym1 = x * x;
    const sym2 = sym1 * x;
    const out = sym2 + x + 5;
    const witness = [1, out, x, sym1, sym2];
    return { witness, out };
  }

  // Pre-configured circuit: Knowledge of factors (p * q = N)
  // Witness: [1, N, p, q]
  static createFactorizationCircuit(): R1CSSystem {
    return {
      variableNames: ['1', 'N', 'p', 'q'],
      constraints: [
        {
          description: 'p * q = N',
          a: [0, 0, 1, 0], // p
          b: [0, 0, 0, 1], // q
          c: [0, 1, 0, 0], // N
        },
      ],
    };
  }
}
