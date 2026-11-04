'use strict';

// 构建配置必须关闭工具栏；误启用立即失败，避免静默恢复浏览器注入。
function initToolbar() {
  throw new Error('TY_BUILD_TOOLBAR_DISABLED：本项目已禁用开发工具栏，请保持 stagewise: false。');
}

module.exports = { initToolbar };
