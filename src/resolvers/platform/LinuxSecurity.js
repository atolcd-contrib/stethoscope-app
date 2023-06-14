import { UNKNOWN } from '../../constants'
import semver from 'semver'
import kmd from '../../lib/kmd'
import sanitizeDebianVersionString from '../../lib/sanitizeDebianVersionString'

export default {
  async firewall (root, args, context) {
    const result = await kmd('firewall', context)
    return result.firewallEnabled === '1'
  },

  async diskEncryption (root, args, context) {
    const result = await kmd('encryption', context)
    return result.disks.encryption === 'true'
  },


  async applications (root, appsToValidate, context) {

    const foundApps = (await kmd('apps', context)).apps

    return appsToValidate.map(({
      exactMatch = false,
      name,
      version: versionRequirement
    }) => {
      let userApp = false

      if (!exactMatch) {
        userApp = foundApps.find((app) => (new RegExp(name, 'ig')).test(app.name))
      } else {
        userApp = foundApps.find((app) => app.name === name)
      }

      // app isn't installed
      if (!userApp) return { name, reason: 'NOT_INSTALLED' }

      // try to massage Debian package versions into something semver-compatible
      // NOTE: this is a "best effort" attempt--do not be surprised if comparing the
      // Debian 'upstream-version' portion of the package version to a semver requirement
      // string does something other than what you expect
      const sanitizedAppVersion = sanitizeDebianVersionString(userApp.version)

      // app is out of date
      if (versionRequirement && !semver.satisfies(sanitizedAppVersion, versionRequirement)) {
        return { name, version: userApp.version, reason: 'OUT_OF_DATE' }
      }

      return { name, version: userApp.version }
    })
  }
}
