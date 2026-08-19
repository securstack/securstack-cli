import { main } from '../bin/securstack.js';

main(process.argv.slice(2)).catch((error) => {
  console.error(error?.message || String(error));
  process.exit(1);
});
