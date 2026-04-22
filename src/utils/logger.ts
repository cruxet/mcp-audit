import chalk from 'chalk';

export type LogLevel = 'quiet' | 'normal' | 'verbose';

export class Logger {
  constructor(private level: LogLevel = 'normal') {}

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  info(msg: string): void {
    if (this.level === 'quiet') return;
    process.stderr.write(msg + '\n');
  }

  debug(msg: string): void {
    if (this.level !== 'verbose') return;
    process.stderr.write(chalk.dim('[debug] ' + msg) + '\n');
  }

  warn(msg: string): void {
    if (this.level === 'quiet') return;
    process.stderr.write(chalk.yellow('[warn] ') + msg + '\n');
  }

  error(msg: string): void {
    process.stderr.write(chalk.red('[error] ') + msg + '\n');
  }
}

export const logger = new Logger();
