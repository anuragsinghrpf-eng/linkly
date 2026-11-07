import { openDatabase } from '../src/db.mjs';
import { loadConfig } from '../src/config.mjs';
const config=loadConfig();
const db=openDatabase(config.databasePath);
const migrations=db.prepare('SELECT version,applied_at FROM schema_migrations ORDER BY version').all();
console.info(`Database ready. Applied schema versions: ${migrations.map(row=>row.version).join(', ')||'none'}.`);
db.close();
