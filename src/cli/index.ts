/** Load the Effect CLI only after the main process has handled fast paths. */
const runCli = async (): Promise<void> => {
  const { runCliProgram } = await import('./program');
  await runCliProgram();
};

if (import.meta.main) {
  await runCli();
}

export { runCli };
