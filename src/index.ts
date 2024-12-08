import * as crypto from 'crypto'
import b32 from 'thirty-two'

export type TwoFactorResponse = {
  code: string,
}

function leftPad(str: string, totalLength: number, pad: string): string {
  if (totalLength + 1 >= str.length) {
    str = Array(totalLength + 1 - str.length).join(pad) + str
  }

  return str
}

export async function generate(key: string): Promise<TwoFactorResponse> {
  const steamPrefix = 'steam://'
  const isSteam = key.toLowerCase().startsWith(steamPrefix)
  if (isSteam) {
    key = key.substr(steamPrefix.length)
  }

  const normalized = key.replace(/\W/g, '').toUpperCase()
  const keyBytes = b32.decode(normalized)

  const currentTime = Math.round(new Date().getTime() / 1000.0)
  const epoch = Math.floor(currentTime / 30)
  const epochBytes = new ArrayBuffer(8)
  const epochBytesView = new DataView(epochBytes)
  epochBytesView.setBigUint64(0, BigInt(epoch), false)

  const digest = crypto.createHmac('sha1', keyBytes).update(epochBytesView).digest()

  const offset = digest[digest.length - 1]! & 0x0F
  const binary = digest.readUInt32BE(offset) & 0x7FFFFFFF

  if (isSteam) {
    const steamChars = '23456789BCDFGHJKMNPQRTVWXY'

    let code = ''
    let remainingCode = binary
    for (let ii = 0; ii != 5; ++ii) {
      code += steamChars[remainingCode % steamChars.length]
      remainingCode = Math.trunc(remainingCode / steamChars.length)
    }

    return {
      code: code,
    }
  } else {
    const code = (binary % Math.pow(10, 6)).toString()
    return {
      code: leftPad(code, 6, '0'),
    }
  }
}
