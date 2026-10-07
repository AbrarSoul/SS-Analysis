
module.exports = async ({ reporter, getBrowser, htmlUrl, strategy, timeout, req, imageExecution, options }) => {
  const opts = Object.assign({}, options)
  const browser = await getBrowser()

  function pageLog (level, message) {
    const maxLogEntrySize = 1000
    let newMsg = message

    if (newMsg.length > maxLogEntrySize) {
      newMsg = `${newMsg.substring(0, maxLogEntrySize)}...`
    }

    reporter.logger[level](newMsg, { timestamp: new Date().getTime(), ...req })
  }

  function trimUrl (url) {
    // this is special case, because phantom logs base64 images content completely into the output
    if (url.startsWith('data:image') && url.length > 100) {
      return `${url.substring(0, 100)}...`
    }

    return url
  }

  const conversionResult = await runWithTimeout(async (executionInfo, reject) => {
    const version = await browser.version()

    if (executionInfo.error) {
      return
    }

    reporter.logger.debug(`Converting with chrome ${version} using ${strategy} strategy`, req)

    const tab = await browser.newPage()

    if (executionInfo.error) {
      return
    }

    tab.on('pageerror', (err) => {
      pageLog('warn', `Page error: ${err.message}${err.stack ? ` , stack: ${err.stack}` : ''}`)
    })

    tab.on('error', (err) => {
      err.workerCrashed = true

      if (!tab.isClosed()) {
        tab.close().catch(() => {})
      }

      reject(err)
    })

    tab.on('console', (m) => {
      pageLog('debug', m.text())
    })

    tab.on('request', (r) => {
      let detail = ''

      if (r.redirectChain().length > 0) {
        detail = ` (redirect from: ${trimUrl(r.redirectChain().slice(-1)[0].url())})`
      }

      pageLog('debug', `Page request: ${r.method()} (${r.resourceType()}) ${trimUrl(r.url())}${detail}`)
    })

    tab.on('requestfinished', (r) => {
      let requestDesc = 'finished'
      let status = ''
      let detail = ''

      if (r.response() != null) {
        if (r.response().status() !== 0) {
          status = ` ${r.response().status()}`
        }

        if (!r.response().ok()) {
          requestDesc = 'failed'
        }
      }

      if (
        r.redirectChain().length > 0 &&
        r.redirectChain().slice(-1)[0].url() === r.url() &&
        r.response() &&
        r.response().headers() &&
        r.response().headers().location != null
      ) {
        detail = ` (redirect to: ${r.response().headers().location})`
      }

      const log = `Page request ${requestDesc}: ${r.method()} (${r.resourceType()})${status} ${trimUrl(r.url())}${detail}`

      if (requestDesc === 'failed') {
        pageLog('warn', log)
      } else {
        pageLog('debug', log)
      }
    })

    tab.on('requestfailed', (r) => {
      pageLog('warn', `Page request failed: ${r.method()} (${r.resourceType()}) ${trimUrl(r.url())}, failure: ${r.failure().errorText}`)
    })

    if (opts.waitForNetworkIddle === true) {
      reporter.logger.debug('Chrome will wait for network iddle before printing', req)
    }

    // this is the same as sending timeout options to the tab.goto
    // but additionally setting it more generally in the tab
    tab.setDefaultNavigationTimeout(timeout)

    await tab.goto(
      htmlUrl,
      opts.waitForNetworkIddle === true
        ? { waitUntil: 'networkidle0' }
        : { }
    )

    if (executionInfo.error) {
      return
    }

    if (opts.waitForJS === true) {
      reporter.logger.debug('Chrome will wait for printing trigger', req)
      await tab.waitForFunction('window.JSREPORT_READY_TO_START === true', { timeout })
    }

    if (executionInfo.error) {
      return
    }

    let newChromeSettings

    if (imageExecution) {
      newChromeSettings = await tab.evaluate(() => window.JSREPORT_CHROME_IMAGE_OPTIONS)
    } else {
      newChromeSettings = await tab.evaluate(() => window.JSREPORT_CHROME_PDF_OPTIONS)
    }

    if (executionInfo.error) {
      return
    }

    if (newChromeSettings != null) {
      delete newChromeSettings.path
    }

    Object.assign(opts, newChromeSettings)

    if (opts.mediaType) {
      if (opts.mediaType !== 'screen' && opts.mediaType !== 'print') {
        throw reporter.createError(`chrome.mediaType must be equal to 'screen' or 'print'`, { weak: true })
      }

      await tab.emulateMedia(opts.mediaType)
    }

    if (executionInfo.error) {
      return
    }

    if (imageExecution) {
      if (opts.type == null) {
        opts.type = 'png'
      }

      if (opts.type !== 'png' && opts.type !== 'jpeg') {
        throw reporter.createError(`chromeImage.type must be equal to 'jpeg' or 'png'`, { weak: true })
      }

      if (opts.type === 'png') {
        delete opts.quality
      }

      if (opts.quality == null) {
        delete opts.quality
      }

      opts.clip = {}

      if (opts.clipX != null) {
        opts.clip.x = opts.clipX
      }

      if (opts.clipY != null) {
        opts.clip.y = opts.clipY
      }

      if (opts.clipWidth != null) {
        opts.clip.width = opts.clipWidth
      }

      if (opts.clipHeight != null) {
        opts.clip.height = opts.clipHeight
      }

      if (Object.keys(opts.clip).length === 0) {
        delete opts.clip
      } else if (
        opts.clip.x == null ||
        opts.clip.y == null ||
        opts.clip.width == null ||
        opts.clip.height == null
      ) {
        throw reporter.createError(`All chromeImage clip properties needs to be specified when at least one of them is passed. Make sure to specify values for "chromeImage.clipX", "chromeImage.clipY", "chromeImage.clipWidth", "chromeImage.clipHeight"`, { weak: true })
      }

      opts.encoding = 'binary'
    } else {
      opts.margin = {
        top: opts.marginTop,
        right: opts.marginRight,
        bottom: opts.marginBottom,
        left: opts.marginLeft
      }

      // if no specified then default to print the background
      if (opts.printBackground == null) {
        opts.printBackground = true
      }
    }

    // don't log header/footer template content
    reporter.logger.debug(`Running chrome with params ${
      JSON.stringify(Object.assign({}, opts, {
        headerTemplate: opts.headerTemplate ? '...' : undefined,
        footerTemplate: opts.footerTemplate ? '...' : undefined
      }))
    }`, req)

    if (opts.scale == null) {
      delete opts.scale
    }

    let result
    let resultType

    if (imageExecution) {
      resultType = opts.type
      result = await tab.screenshot(opts)
    } else {
      resultType = 'pdf'
      result = await tab.pdf(opts)
    }

    if (executionInfo.error) {
      return
    }

    return {
      tab,
      type: resultType,
      content: result
    }
  }, timeout, `${imageExecution ? 'image' : 'pdf'} generation not completed after ${timeout}ms`)

  return conversionResult
}

function runWithTimeout (fn, ms, msg) {
  return new Promise(async (resolve, reject) => {
    let resolved = false

    const info = {
      // information to pass to fn to ensure it can cancel
      // things if it needs to
      error: null
    }

    const timer = setTimeout(() => {
      const err = new Error(`Timeout Error: ${msg}`)
      err.workerTimeout = true
      info.error = err
      resolved = true
      reject(err)
    }, ms)

    try {
      const result = await fn(info, (err) => {
        if (resolved) {
          return
        }

        resolved = true
        clearTimeout(timer)
        info.error = err
        reject(err)
      })

      if (resolved) {
        return
      }

      resolve(result)
    } catch (e) {
      if (resolved) {
        return
      }

      reject(e)
    } finally {
      clearTimeout(timer)
    }
  })
}
