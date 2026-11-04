'use strict';

// CLI 仅使用 render(...).string；保留文字，不复制第三方字体、ANSI效果或实现。
function render(value) {
  return { string: String(value ?? '') };
}

module.exports = { render };
