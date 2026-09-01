import { closeDatabase, runMigrations } from './database.mjs'

try { await runMigrations(); console.log('Database migrations completed.') }
finally { await closeDatabase() }

