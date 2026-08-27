import { environmentWithPackageDist } from '../lib/environment';
import { resolveTripwireCommand } from '../lib/runtime-command';

type LaunchMode = 'cli' | 'hook';

const launchTripwire = (mode: LaunchMode): never => {
  const command = resolveTripwireCommand({ moduleUrl: import.meta.url });
  const modeFlag = mode === 'hook' ? '--tripwire-hook' : '--tripwire-force-cli';
  const packageDist = import.meta.dirname;
  const result = Bun.spawnSync(
    [command.executable, ...command.arguments, modeFlag, ...process.argv.slice(2)],
    {
      stderr: 'inherit',
      env: environmentWithPackageDist(packageDist),
      stdin: 'inherit',
      stdout: 'inherit',
    },
  );
  process.exit(result.exitCode);
};

export { launchTripwire };
