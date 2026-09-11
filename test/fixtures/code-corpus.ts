import { compatibilityPairs } from './code-compatibility';
import { compatibilityAttacks } from './code-compatibility-attacks';
import { codeFixtures } from './embedded-code';
import { projectCommandFixtures } from './project-commands';
import { writeParityFixtures } from './write-parity';

const allCodeFixtures = [
  ...writeParityFixtures,
  ...projectCommandFixtures,
  ...codeFixtures,
  ...compatibilityPairs.flatMap((pair) => [
    { name: `${pair.name}: allow`, command: pair.allow, allowed: true },
    { name: `${pair.name}: block`, command: pair.block, allowed: false },
  ]),
  ...compatibilityAttacks.map((command, index) => ({
    name: `Compatibility attack ${index}`,
    command,
    allowed: false,
  })),
];

export { allCodeFixtures };
