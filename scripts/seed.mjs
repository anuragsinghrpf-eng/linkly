import { openDatabase, seedDefaults } from '../src/db.mjs';
import { loadConfig } from '../src/config.mjs';
const config=loadConfig();
const db=openDatabase(config.databasePath);
seedDefaults(db);
console.info('Default website settings and five unlock steps are present. No demo users, clicks, or earnings were added.');
db.close();
