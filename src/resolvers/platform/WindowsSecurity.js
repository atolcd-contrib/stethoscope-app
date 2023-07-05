import semver from '../../lib/patchedSemver'
import kmd from '../../lib/kmd'
import { UNKNOWN, DEFAULT_WIN32_APP_REGISTRY_PATH } from '../../constants'

export default {

  async diskEncryption (root, args, context) {
    const device = await kmd('os', context)
    // workspaces don't support disk encryption - bail
    if (device.system.platform === 'awsWorkspace') {
      return true
    }

    const disk = await kmd('encryption', context)

    if (disk.bitlockerStatus) {
      return disk.bitlockerStatus === 'ON'
    }
    return false
  },


  async firewall (root, args, context) {
    const result = await kmd('firewall', context)
    return result.firewalls.every(fw => fw.status === 'True')
  },

  async antivirus (root, args, context) {
    const result = await kmd('antivirus', context)
    return result.defender === 'True'
  },

  async applications (root, appsToValidate, context) {
    // gather set of optional registry path overrides from policy
    const registryPathOverrides = new Set()
    appsToValidate.map(({ paths = {} }) => {
      registryPathOverrides.add(paths.win32 || DEFAULT_WIN32_APP_REGISTRY_PATH)
    })

    const paths = Array.from(registryPathOverrides)

    let foundApps = []
    for (const path of paths) {
      const appsAtRegPath = await kmd('apps', context, { REGISTRY_PATH: path })
      foundApps = foundApps.concat(appsAtRegPath.apps)
    }

    return appsToValidate.map(({
      exactMatch = false,
      name,
      version
    }) => {
      let userApp = false

      if (!exactMatch) {
        userApp = foundApps.find((app) => (new RegExp(name, 'ig')).test(app.name))
      } else {
        userApp = foundApps.find((app) => app.name === name)
      }

      // app isn't installed
      if (!userApp) return { name, reason: 'NOT_INSTALLED' }
      // app is out of date
      if (version && !semver.satisfies(userApp.version, version)) {
        return { name, version: userApp.version, reason: 'OUT_OF_DATE' }
      }

      return { name, version: userApp.version }
    })
  }
}
