// read-lines.ts
import { readFileSync } from 'fs';

/**
 * Reads a text file and returns its lines as an array.
 * Empty lines are kept; change the filter if you want to drop them.
 *
 * @param path  Path to the file (relative or absolute).
 * @returns     Array of lines without the trailing newline characters.
 */
export function readLines(path: string): string[] {
  return readFileSync(path, 'utf8')   // read entire file as UTF-8
    .split(/\r?\n/);                  // split on LF or CRLF
}

/* ---------- usage example ---------- */
if (require.main === module) {
  const lines = readLines(process.argv[2] ?? 'english.txt');
  console.log(lines);
}