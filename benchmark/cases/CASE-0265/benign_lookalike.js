// Standalone example of the same shape: skip rendering a "welcome back"
// banner unless the viewer's OWN locally-stored preference flag says to
// show it (never data another user's record controls), so a missing flag
// is a UX default, not an authorization gap.
function renderDashboardBanner (viewer, content) {
  const showBanner = Boolean(viewer.preferences && viewer.preferences.showWelcomeBanner)
  if (!showBanner) return content
  content.banner = 'Welcome back, ' + viewer.fullname
  return content
}

module.exports = { renderDashboardBanner }
