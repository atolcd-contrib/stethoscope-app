import { NUDGE, DEFAULT_DARWIN_APP_PATH } from '../../constants'
import kmd from '../../lib/kmd'
import os from 'os'

const MacSecurity = {
  async automaticAppUpdates (root, args, context) {
    const result = await kmd('com.apple.commerce', context)
    return result.updates.autoUpdate !== '0'
  },

  async automaticDownloadUpdates (root, args, context) {
    const result = await kmd('com.apple.SoftwareUpdate', context)
    return result.updates.automaticDownload !== '0'
  },

  async automaticConfigDataInstall (root, args, context) {
    const result = await kmd('com.apple.SoftwareUpdate', context)
    return result.updates.configDataInstall !== '0'
  },

  async automaticSecurityUpdates (root, args, context) {
    const result = await kmd('com.apple.SoftwareUpdate', context)
    return result.updates.criticalUpdateInstall !== '0'
  },

  async automaticOsUpdates (root, args, context) {
    const result = await kmd('com.apple.SoftwareUpdate', context)
    return result.updates.automaticallyInstallMacOSUpdates !== '0'
  },

  async automaticCheckEnabled (root, args, context) {
    const result = await kmd('com.apple.SoftwareUpdate', context)
    return result.updates.automaticCheckEnabled !== '0'
  },

  async applications (root, appsToValidate, context) {
    const requests = appsToValidate.map(({ name, paths = {} }) => {
      const variables = {
        NAME: name,
        PATH: (paths.darwin || DEFAULT_DARWIN_APP_PATH).replace(/^~/, os.homedir())
      }
      return kmd('app', context, variables)
    })
    return Promise.all(requests)
  },

  async diskEncryption (root, args, context) {
    const result = await kmd('file-vault', context)
    return result.fileVaultEnabled === 'true'
  },

  async firewall (root, args, context) {
    const result = await kmd('firewall', context)
    return parseInt(result.firewallEnabled, 10) > 0
  },

}

export default MacSecurity
