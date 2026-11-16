/* 首帧主题引导：必须在 <style>/<link> 之前执行，否则深色启动会先闪一帧白底。
 * 只做一件事：按 localStorage 里的 theme 立刻给 <html> 设 data-theme。
 * 之后 app.js 的 applyTheme() 会再设一次（同值），并接管 system 档的媒体查询监听。
 * 单独成文件是因为 CSP 是 script-src 'self'，不允许内联脚本。 */
(function () {
  try {
    var want = localStorage.getItem('theme') || 'system';
    var dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.documentElement.setAttribute('data-theme', want === 'system' ? (dark ? 'dark' : 'light') : want);
  } catch (e) {
    /* 存储不可用时按浅色走：宁可少一次记忆，也不要白屏。 */
  }
})();
