import bcrypt from 'bcryptjs'
import { createInterface } from 'node:readline/promises'
import { stdin as input, stdout as output } from 'node:process'

const rl = createInterface({ input, output })
const password = await rl.question('Password: ')
rl.close()

if (!password) throw new Error('Password cannot be empty')
console.log(await bcrypt.hash(password, 12))
